//! AMR-NB gain decode tier — 3GPP TS 26.073 `gc_pred.c`, `dec_gain.c`, `d_gain_c.c`.
//! Ported bit-exact.
//!
//! The codebook gain is MA-predicted from the innovation energy and the history of quantized
//! energies ([`gc_pred`] + [`GcPredState`]). [`dec_gain`] (modes MR475..MR102) reads both pitch and
//! code gain from a per-mode VQ table; [`d_gain_code`] (MR795/MR122) reads only the code gain (the
//! pitch gain comes from [`crate::amr::nb::pitch::d_gain_pitch`]). All paths update the predictor
//! via [`gc_pred_update`].

use crate::amr::basic_ops::{
    add, extract_h, extract_l, l_mac, l_mult, l_shl, l_shr, mult, round_word, shl, shr_r, sub,
};
use crate::amr::math_op::{log2, log2_norm, pow2};
use crate::amr::nb::constants::L_SUBFR;
use crate::amr::nb::gain_tables::QUA_GAIN_CODE;
use crate::amr::nb::gain_vq_tables::{TABLE_GAIN_HIGHRATES, TABLE_GAIN_LOWRATES, TABLE_GAIN_MR475};
use crate::amr::oper_32b::{l_comp, l_extract, mpy_32_16};
use crate::amr::AmrNbMode;

/// Number of MA prediction taps (`gc_pred.c` `NPRED`).
const NPRED: usize = 4;
/// MA prediction coefficients, Q13 (`gc_pred.c` `pred`).
const PRED: [i16; NPRED] = [5571, 4751, 2785, 1556];
/// MA prediction coefficients, Q6 (`gc_pred.c` `pred_MR122`).
const PRED_MR122: [i16; NPRED] = [44, 37, 22, 12];
/// Average innovation energy, Q17 (`gc_pred.c` `MEAN_ENER_MR122` = 36/(20*log10(2))).
const MEAN_ENER_MR122: i32 = 783741;
/// Minimum quantized energy, -14 dB, Q10 (`gc_pred.c` `MIN_ENERGY`).
const MIN_ENERGY: i16 = -14336;
/// Minimum quantized energy for MR122, Q10 (`gc_pred.c` `MIN_ENERGY_MR122`).
const MIN_ENERGY_MR122: i16 = -2381;

/// Mode index for `MR122` (= [`AmrNbMode::Mr1220`] frame type), used for the MR122-specific gain
/// scalings.
const MODE_MR122: usize = AmrNbMode::Mr1220 as usize;

/// Codebook-gain MA predictor state (`gc_pred.h` `gc_predState`).
#[derive(Debug, Clone)]
pub struct GcPredState {
    /// Past quantized energies, Q10 (20*log10 domain) (`past_qua_en[NPRED]`).
    pub past_qua_en: [i16; NPRED],
    /// Past quantized energies, Q10 (log2 domain) (`past_qua_en_MR122[NPRED]`).
    pub past_qua_en_mr122: [i16; NPRED],
}

impl Default for GcPredState {
    fn default() -> Self {
        Self::new()
    }
}

impl GcPredState {
    /// Reset: seed both energy histories with their minima (`gc_pred_reset`).
    #[must_use]
    pub fn new() -> Self {
        Self {
            past_qua_en: [MIN_ENERGY; NPRED],
            past_qua_en_mr122: [MIN_ENERGY_MR122; NPRED],
        }
    }
}

/// Result of [`gc_pred`]: the predicted gain factor `gcode0 = 2^(exp + frac)` plus, for MR795, the
/// innovation-energy `(exp_en, frac_en)`.
#[derive(Debug, Clone, Copy, Default)]
pub struct GcPredOut {
    /// Exponent of the predicted gain factor, Q0.
    pub exp_gcode0: i16,
    /// Fraction of the predicted gain factor, Q15.
    pub frac_gcode0: i16,
    /// Exponent of the innovation energy, Q0 (MR795 only).
    pub exp_en: i16,
    /// Fraction of the innovation energy, Q15 (MR795 only).
    pub frac_en: i16,
}

/// MA prediction of the innovation energy → predicted codebook gain factor (`gc_pred.c` `gc_pred`).
/// `code` is the innovation vector (Q12 for MR122, Q13 otherwise). Reads but does not mutate `st`.
#[must_use]
pub fn gc_pred(st: &GcPredState, mode: usize, code: &[i16]) -> GcPredOut {
    let mut out = GcPredOut::default();

    // ener_code = sum(code[i]^2)
    let mut ener_code: i32 = 0;
    for &c in code.iter().take(L_SUBFR) {
        ener_code = l_mac(ener_code, c, c);
    }

    if mode == MODE_MR122 {
        // ener_code = ener_code / 40  (1/40 = 26214 Q20)
        let mut ener_code = l_mult(round_word(ener_code), 26214); // Q30
                                                                  // ener_code = 1/2 * Log2(ener_code)
        let (exp, frac) = log2(ener_code);
        ener_code = l_comp(sub(exp, 30), frac); // Q17

        // predicted energy
        let mut ener = MEAN_ENER_MR122;
        for (&past, &pred) in st.past_qua_en_mr122.iter().zip(PRED_MR122.iter()) {
            ener = l_mac(ener, past, pred);
        }

        let ener = l_shr(crate::amr::basic_ops::l_sub(ener, ener_code), 1); // Q16
        let (hi, lo) = l_extract(ener);
        out.exp_gcode0 = hi;
        out.frac_gcode0 = lo;
    } else {
        // all modes except MR122
        let exp_code = crate::amr::basic_ops::norm_l(ener_code);
        let ener_code_n = l_shl(ener_code, exp_code);

        // Log2 = log2 + 27 (Log2_norm)
        let (exp, frac) = log2_norm(ener_code_n, exp_code);

        // fact = 10/log2(10) = 24660 Q13
        let mut l_tmp = mpy_32_16(exp, frac, -24660); // Q14

        // means_ener constant per mode
        if mode == AmrNbMode::Mr1020 as usize {
            l_tmp = l_mac(l_tmp, 16678, 64); // mean 33 dB
        } else if mode == AmrNbMode::Mr795 as usize {
            out.frac_en = extract_h(ener_code_n);
            out.exp_en = sub(-11, exp_code);
            l_tmp = l_mac(l_tmp, 17062, 64); // mean 36 dB
        } else if mode == AmrNbMode::Mr740 as usize {
            l_tmp = l_mac(l_tmp, 32588, 32); // mean 30 dB
        } else if mode == AmrNbMode::Mr670 as usize {
            l_tmp = l_mac(l_tmp, 32268, 32); // mean 28.75 dB
        } else {
            // MR59, MR515, MR475
            l_tmp = l_mac(l_tmp, 16678, 64); // mean 33 dB
        }

        l_tmp = l_shl(l_tmp, 10); // Q24
        for (&pred, &past) in PRED.iter().zip(st.past_qua_en.iter()) {
            l_tmp = l_mac(l_tmp, pred, past); // Q24
        }

        let gcode0 = extract_h(l_tmp); // Q8

        // gcode0 = pow(2, 0.166*gcode0). 5439 Q15 for MR74 (IS641), else 5443.
        let mut l_tmp = if mode == AmrNbMode::Mr740 as usize {
            l_mult(gcode0, 5439)
        } else {
            l_mult(gcode0, 5443)
        };
        l_tmp = l_shr(l_tmp, 8); // Q16
        let (hi, lo) = l_extract(l_tmp);
        out.exp_gcode0 = hi;
        out.frac_gcode0 = lo;
    }

    out
}

/// Update the MA predictor with the last quantized energy (`gc_pred.c` `gc_pred_update`).
/// `qua_ener_mr122` is Q10 log2(g); `qua_ener` is Q10 20*log10(g).
pub fn gc_pred_update(st: &mut GcPredState, qua_ener_mr122: i16, qua_ener: i16) {
    for i in (1..NPRED).rev() {
        st.past_qua_en[i] = st.past_qua_en[i - 1];
        st.past_qua_en_mr122[i] = st.past_qua_en_mr122[i - 1];
    }
    st.past_qua_en_mr122[0] = qua_ener_mr122;
    st.past_qua_en[0] = qua_ener;
}

/// Decode pitch + code gain from the per-mode VQ (`dec_gain.c` `Dec_gain`), for MR475..MR102
/// (excluding MR795/MR122). Returns `(gain_pit Q14, gain_cod)` and updates the predictor.
#[must_use]
pub fn dec_gain(
    pred_state: &mut GcPredState,
    mode: usize,
    index: i16,
    code: &[i16],
    even_subfr: i16,
) -> (i16, i16) {
    let mut index = shl(index, 2);

    let gain_pit;
    let g_code;
    let qua_ener_mr122;
    let qua_ener;

    if mode == AmrNbMode::Mr1020 as usize
        || mode == AmrNbMode::Mr740 as usize
        || mode == AmrNbMode::Mr670 as usize
    {
        let p = index as usize;
        gain_pit = TABLE_GAIN_HIGHRATES[p];
        g_code = TABLE_GAIN_HIGHRATES[p + 1];
        qua_ener_mr122 = TABLE_GAIN_HIGHRATES[p + 2];
        qua_ener = TABLE_GAIN_HIGHRATES[p + 3];
    } else if mode == AmrNbMode::Mr475 as usize {
        index = add(index, shl(sub(1, even_subfr), 1));
        let p = index as usize;
        gain_pit = TABLE_GAIN_MR475[p];
        g_code = TABLE_GAIN_MR475[p + 1];

        // qua_ener / qua_ener_MR122 are computed (not stored) for MR475.
        // Log2(g_code Q12) = log2(g_code) + 12.
        let (exp, frac) = log2(crate::amr::basic_ops::l_deposit_l(g_code));
        let exp = sub(exp, 12);
        qua_ener_mr122 = add(shr_r(frac, 5), shl(exp, 10));
        // 24660 Q12 ~= 20*log10(2)
        let l_tmp = mpy_32_16(exp, frac, 24660);
        qua_ener = round_word(l_shl(l_tmp, 13)); // Q13 -> Q10
    } else {
        // MR515, MR59
        let p = index as usize;
        gain_pit = TABLE_GAIN_LOWRATES[p];
        g_code = TABLE_GAIN_LOWRATES[p + 1];
        qua_ener_mr122 = TABLE_GAIN_LOWRATES[p + 2];
        qua_ener = TABLE_GAIN_LOWRATES[p + 3];
    }

    // predict codebook gain
    let pred = gc_pred(pred_state, mode, code);
    let gcode0 = extract_l(pow2(14, pred.frac_gcode0));

    let l_tmp = l_mult(g_code, gcode0);
    let l_tmp = l_shr(l_tmp, sub(10, pred.exp_gcode0));
    let gain_cod = extract_h(l_tmp);

    gc_pred_update(pred_state, qua_ener_mr122, qua_ener);

    (gain_pit, gain_cod)
}

/// Decode the fixed-codebook gain (`d_gain_c.c` `d_gain_code`), for MR795 and MR122. Returns the
/// code gain and updates the predictor. (The pitch gain for these modes comes from `d_gain_pitch`.)
#[must_use]
pub fn d_gain_code(pred_state: &mut GcPredState, mode: usize, index: i16, code: &[i16]) -> i16 {
    let pred = gc_pred(pred_state, mode, code);
    let p = add(add(index, index), index) as usize; // index * 3

    let gain_code = if mode == MODE_MR122 {
        let mut gcode0 = extract_l(pow2(pred.exp_gcode0, pred.frac_gcode0));
        gcode0 = shl(gcode0, 4);
        shl(mult(gcode0, QUA_GAIN_CODE[p]), 1)
    } else {
        let gcode0 = extract_l(pow2(14, pred.frac_gcode0));
        let l_tmp = l_mult(QUA_GAIN_CODE[p], gcode0);
        let l_tmp = l_shr(l_tmp, sub(9, pred.exp_gcode0));
        extract_h(l_tmp)
    };

    let qua_ener_mr122 = QUA_GAIN_CODE[p + 1];
    let qua_ener = QUA_GAIN_CODE[p + 2];
    gc_pred_update(pred_state, qua_ener_mr122, qua_ener);

    gain_code
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reset_seeds_energy_histories_with_minima() {
        let st = GcPredState::new();
        assert_eq!(st.past_qua_en, [MIN_ENERGY; NPRED]);
        assert_eq!(st.past_qua_en_mr122, [MIN_ENERGY_MR122; NPRED]);
    }

    #[test]
    fn gc_pred_update_shifts_history() {
        let mut st = GcPredState::new();
        gc_pred_update(&mut st, 100, 200);
        assert_eq!(st.past_qua_en_mr122[0], 100);
        assert_eq!(st.past_qua_en[0], 200);
        assert_eq!(st.past_qua_en_mr122[1], MIN_ENERGY_MR122);
        gc_pred_update(&mut st, 101, 201);
        assert_eq!(st.past_qua_en_mr122[0], 101);
        assert_eq!(st.past_qua_en_mr122[1], 100);
    }

    #[test]
    fn dec_gain_runs_and_updates_state_mr59() {
        let mut st = GcPredState::new();
        let code = [100i16; L_SUBFR];
        let before = st.past_qua_en;
        let (gp, gc) = dec_gain(&mut st, AmrNbMode::Mr590 as usize, 0, &code, 1);
        // gain_pit is the table[0] entry; both gains are finite and the predictor advanced.
        assert_eq!(gp, TABLE_GAIN_LOWRATES[0]);
        assert!(gc >= 0);
        assert_ne!(st.past_qua_en, before);
    }

    #[test]
    fn dec_gain_mr475_even_odd_subframe_offset() {
        // MR475 uses evenSubfr to pick the odd/even pair within a 4-wide row.
        let mut st_even = GcPredState::new();
        let mut st_odd = GcPredState::new();
        let code = [50i16; L_SUBFR];
        let (gp_even, _) = dec_gain(&mut st_even, AmrNbMode::Mr475 as usize, 0, &code, 1);
        let (gp_odd, _) = dec_gain(&mut st_odd, AmrNbMode::Mr475 as usize, 0, &code, 0);
        // index 0: even -> table[0], odd -> table[0 + 2]. They are distinct table entries.
        assert_eq!(gp_even, TABLE_GAIN_MR475[0]);
        assert_eq!(gp_odd, TABLE_GAIN_MR475[2]);
    }

    #[test]
    fn d_gain_code_runs_mr122_and_mr795() {
        let code = [80i16; L_SUBFR];
        let mut st122 = GcPredState::new();
        let g122 = d_gain_code(&mut st122, MODE_MR122, 5, &code);
        assert!(g122 >= 0);
        assert_eq!(st122.past_qua_en_mr122[0], QUA_GAIN_CODE[5 * 3 + 1]);

        let mut st795 = GcPredState::new();
        let g795 = d_gain_code(&mut st795, AmrNbMode::Mr795 as usize, 5, &code);
        assert!(g795 >= 0);
    }

    #[test]
    fn gc_pred_mr122_vs_other_paths_differ() {
        // The two code paths produce different predicted factors for the same input.
        let st = GcPredState::new();
        let code = [200i16; L_SUBFR];
        let mr122 = gc_pred(&st, MODE_MR122, &code);
        let mr59 = gc_pred(&st, AmrNbMode::Mr590 as usize, &code);
        assert!(
            mr122.frac_gcode0 != mr59.frac_gcode0 || mr122.exp_gcode0 != mr59.exp_gcode0,
            "MR122 and MR59 gc_pred paths should differ"
        );
    }
}
