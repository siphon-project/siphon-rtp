//! AMR-WB pitch / codebook gain decoder (3GPP TS 26.173 `d_gain2.c`), ported bit-exact.
//!
//! [`d_gain2`] decodes the quantized pitch gain (Q14) and code gain (Q16) from the 6-bit (mode 0)
//! or 7-bit codebook index, running an MA energy predictor over the past quantized code energies.
//! The predictor and the gain history live in the decoder's `dec_gain[23]` memory, laid out exactly
//! as the C reference's `mem[23]` so that lag concealment (which reads `&dec_gain[17]`) stays
//! byte-compatible:
//!
//! | index | field            | init           |
//! |-------|------------------|----------------|
//! | 0..4  | `past_qua_en[4]` | `-14336` (Q10) |
//! | 4     | `past_gain_pit`  | 0              |
//! | 5     | `past_gain_code` | 0              |
//! | 6     | `prev_gc`        | 0              |
//! | 7..12 | `pbuf[5]`        | 0              |
//! | 12..17| `gbuf[5]`        | 0              |
//! | 17..22| `pbuf2[5]`       | 0              |
//! | 22    | `seed`           | 21845          |

use super::tables::{T_QUA_GAIN6B, T_QUA_GAIN7B};
use crate::amr::basic_ops::{
    add, extract_h, extract_l, l_deposit_h, l_deposit_l, l_mac, l_mult, l_shl, l_shr, l_sub, mult,
    round_word, sub,
};
use crate::amr::math_op::{dot_product12, isqrt_n, log2, pow2};
use crate::amr::oper_32b::{l_extract, mpy_32_16};

/// Mean code energy (dB) used by the gain predictor.
const MEAN_ENER: i16 = 30;
/// MA prediction coefficients `{0.5, 0.4, 0.3, 0.2}` in Q13.
const PRED: [i16; 4] = [4096, 3277, 2458, 1638];

/// BFI pitch-gain attenuation per BFH state — unusable / usable frame (Q15).
const PDOWN_UNUSABLE: [i16; 7] = [32767, 31130, 29491, 24576, 7537, 1638, 328];
const CDOWN_UNUSABLE: [i16; 7] = [32767, 16384, 8192, 8192, 8192, 4915, 3277];
const PDOWN_USABLE: [i16; 7] = [32767, 32113, 31457, 24576, 7537, 1638, 328];
const CDOWN_USABLE: [i16; 7] = [32767, 32113, 32113, 32113, 32113, 32113, 22938];

/// Number of `Word16` slots in the decoder's gain memory.
pub const DEC_GAIN_LEN: usize = 23;

/// Initialize the gain-decoder memory to the reference's `Init_D_gain2` state.
pub fn init_d_gain2(mem: &mut [i16; DEC_GAIN_LEN]) {
    mem.fill(0);
    mem[0] = -14336; // past_qua_en[0..4] = -14.0 in Q10
    mem[1] = -14336;
    mem[2] = -14336;
    mem[3] = -14336;
    mem[22] = 21845; // seed
}

/// Median of `{x[-2], x[-1], x[0], x[1], x[2]}` (`p_med_ol.c median5`); `center` is the index of
/// `x[0]` so the window is `slice[center-2 ..= center+2]`.
fn median5(slice: &[i16], center: usize) -> i16 {
    let mut x1 = slice[center - 2];
    let mut x2 = slice[center - 1];
    let mut x3 = slice[center];
    let mut x4 = slice[center + 1];
    let mut x5 = slice[center + 2];

    if sub(x2, x1) < 0 {
        core::mem::swap(&mut x1, &mut x2);
    }
    if sub(x3, x1) < 0 {
        core::mem::swap(&mut x1, &mut x3);
    }
    if sub(x4, x1) < 0 {
        core::mem::swap(&mut x1, &mut x4);
    }
    if sub(x5, x1) < 0 {
        x5 = x1;
    }
    if sub(x3, x2) < 0 {
        core::mem::swap(&mut x2, &mut x3);
    }
    if sub(x4, x2) < 0 {
        core::mem::swap(&mut x2, &mut x4);
    }
    if sub(x5, x2) < 0 {
        x5 = x2;
    }
    if sub(x4, x3) < 0 {
        x3 = x4;
    }
    if sub(x5, x3) < 0 {
        x3 = x5;
    }
    x3
}

/// Decode the pitch and codebook gains (`D_gain2`).
///
/// Returns `(gain_pit Q14, gain_code Q16)`. `index` is the quantizer index, `nbits` is 6 (mode 0)
/// or 7, `code` is the Q9 innovative vector (post pitch-sharpening), and `mem` is the `dec_gain[23]`
/// state. `bfi`/`prev_bfi`/`state`/`unusable_frame`/`vad_hist` drive the erasure concealment path.
#[allow(clippy::too_many_arguments)]
pub fn d_gain2(
    index: i16,
    nbits: i16,
    code: &[i16],
    l_subfr: usize,
    bfi: bool,
    prev_bfi: bool,
    state: i16,
    unusable_frame: bool,
    vad_hist: i16,
    mem: &mut [i16; DEC_GAIN_LEN],
) -> (i16, i32) {
    // mem field offsets (see module doc / Init_D_gain2).
    const PAST_QUA_EN: usize = 0;
    const PAST_GAIN_PIT: usize = 4;
    const PAST_GAIN_CODE: usize = 5;
    const PREV_GC: usize = 6;
    const PBUF: usize = 7;
    const GBUF: usize = 12;
    const PBUF2: usize = 17;

    // L_tmp = 1.0 / sqrt(energy of code / L_subfr).
    let (mut l_tmp, mut exp) = dot_product12(code, code, l_subfr);
    exp = sub(exp, 18 + 6); // -18 (code in Q9), -6 (/L_subfr)
    isqrt_n(&mut l_tmp, &mut exp);
    let gcode_inov = extract_h(l_shl(l_tmp, sub(exp, 3))); // g_code_inov in Q12

    if bfi {
        let mut tmp = median5(mem, PBUF + 2);
        mem[PAST_GAIN_PIT] = tmp;
        if sub(mem[PAST_GAIN_PIT], 15565) > 0 {
            mem[PAST_GAIN_PIT] = 15565; // 0.95 in Q14
        }
        let gain_pit = if unusable_frame {
            mult(PDOWN_UNUSABLE[state as usize], mem[PAST_GAIN_PIT])
        } else {
            mult(PDOWN_USABLE[state as usize], mem[PAST_GAIN_PIT])
        };

        tmp = median5(mem, GBUF + 2);
        if sub(vad_hist, 2) > 0 {
            mem[PAST_GAIN_CODE] = tmp;
        } else if unusable_frame {
            mem[PAST_GAIN_CODE] = mult(CDOWN_UNUSABLE[state as usize], tmp);
        } else {
            mem[PAST_GAIN_CODE] = mult(CDOWN_USABLE[state as usize], tmp);
        }

        // Update the table of past quantized energies.
        let mut l_en = l_mult(mem[PAST_QUA_EN], 8192);
        l_en = l_mac(l_en, mem[PAST_QUA_EN + 1], 8192);
        l_en = l_mac(l_en, mem[PAST_QUA_EN + 2], 8192);
        l_en = l_mac(l_en, mem[PAST_QUA_EN + 3], 8192);
        let mut qua_ener = extract_h(l_en);
        qua_ener = sub(qua_ener, 3072); // -3 in Q10
        if sub(qua_ener, -14336) < 0 {
            qua_ener = -14336; // -14 in Q10
        }
        mem[PAST_QUA_EN + 3] = mem[PAST_QUA_EN + 2];
        mem[PAST_QUA_EN + 2] = mem[PAST_QUA_EN + 1];
        mem[PAST_QUA_EN + 1] = mem[PAST_QUA_EN];
        mem[PAST_QUA_EN] = qua_ener;

        for i in 1..5 {
            mem[GBUF + i - 1] = mem[GBUF + i];
        }
        mem[GBUF + 4] = mem[PAST_GAIN_CODE];
        for i in 1..5 {
            mem[PBUF + i - 1] = mem[PBUF + i];
        }
        mem[PBUF + 4] = mem[PAST_GAIN_PIT];

        // past_gain_code(Q3) * gcode_inov(Q12) => Q16
        let gain_cod = l_mult(mem[PAST_GAIN_CODE], gcode_inov);
        return (gain_pit, gain_cod);
    }

    // gcode0 = Sum pred[i]*past_qua_en[i] + mean_ener - ener_code.
    let mut l_acc = l_deposit_h(MEAN_ENER); // Q16
    l_acc = l_shl(l_acc, 8); // Q16 -> Q24
    l_acc = l_mac(l_acc, PRED[0], mem[PAST_QUA_EN]);
    l_acc = l_mac(l_acc, PRED[1], mem[PAST_QUA_EN + 1]);
    l_acc = l_mac(l_acc, PRED[2], mem[PAST_QUA_EN + 2]);
    l_acc = l_mac(l_acc, PRED[3], mem[PAST_QUA_EN + 3]);
    let mut gcode0 = extract_h(l_acc); // Q24 -> Q8

    // gcode0 = pow(2, 0.166096*gcode0).
    l_acc = l_mult(gcode0, 5443); // *0.166096 in Q15 -> Q24
    l_acc = l_shr(l_acc, 8); // Q24 -> Q16
    let (mut exp_gcode0, frac) = l_extract(l_acc);
    gcode0 = extract_l(pow2(14, frac));
    exp_gcode0 = sub(exp_gcode0, 14);

    // Read the quantized gains.
    let table: &[i16] = if nbits == 6 { &T_QUA_GAIN6B } else { &T_QUA_GAIN7B };
    let base = add(index, index) as usize;
    let gain_pit = table[base]; // Q14
    let g_code = table[base + 1]; // Q11

    let mut l_gain = l_mult(g_code, gcode0); // Q11*Q0 -> Q12
    l_gain = l_shl(l_gain, add(exp_gcode0, 4)); // Q12 -> Q16
    let mut gain_cod = l_gain;

    if prev_bfi {
        let l_clip = l_mult(mem[PREV_GC], 5120); // prev_gc(Q3) * 1.25(Q12) = Q16
        if l_sub(gain_cod, l_clip) > 0 && l_sub(gain_cod, 6_553_600) > 0 {
            gain_cod = l_clip;
        }
    }

    // Keep past gain code in Q3 for frame erasure (can saturate).
    mem[PAST_GAIN_CODE] = round_word(l_shl(gain_cod, 3));
    mem[PAST_GAIN_PIT] = gain_pit;
    mem[PREV_GC] = mem[PAST_GAIN_CODE];

    for i in 1..5 {
        mem[GBUF + i - 1] = mem[GBUF + i];
    }
    mem[GBUF + 4] = mem[PAST_GAIN_CODE];
    for i in 1..5 {
        mem[PBUF + i - 1] = mem[PBUF + i];
    }
    mem[PBUF + 4] = mem[PAST_GAIN_PIT];
    for i in 1..5 {
        mem[PBUF2 + i - 1] = mem[PBUF2 + i];
    }
    mem[PBUF2 + 4] = mem[PAST_GAIN_PIT];

    // Adjust gain according to energy of code.
    let (e, f) = l_extract(gain_cod);
    let l_adj = mpy_32_16(e, f, gcode_inov);
    gain_cod = l_shl(l_adj, 3); // gcode_inov in Q12

    // qua_ener = 6.0206 * (log2(g_code) - 11).
    let l_g = l_deposit_l(g_code);
    let (mut e2, f2) = log2(l_g);
    e2 = sub(e2, 11);
    let l_q = mpy_32_16(e2, f2, 24660); // x 6.0206 in Q12
    let qua_ener = extract_l(l_shr(l_q, 3)); // result in Q10

    mem[PAST_QUA_EN + 3] = mem[PAST_QUA_EN + 2];
    mem[PAST_QUA_EN + 2] = mem[PAST_QUA_EN + 1];
    mem[PAST_QUA_EN + 1] = mem[PAST_QUA_EN];
    mem[PAST_QUA_EN] = qua_ener;

    (gain_pit, gain_cod)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_matches_reference_layout() {
        let mut mem = [1i16; DEC_GAIN_LEN];
        init_d_gain2(&mut mem);
        assert_eq!(&mem[0..4], &[-14336, -14336, -14336, -14336]);
        assert!(mem[4..22].iter().all(|&v| v == 0));
        assert_eq!(mem[22], 21845);
    }

    #[test]
    fn median5_returns_the_middle_value() {
        // Window of {1,5,2,8,3} -> sorted {1,2,3,5,8} -> median 3.
        let slice = [0i16, 0, 1, 5, 2, 8, 3];
        assert_eq!(median5(&slice, 4), 3);
    }

    #[test]
    fn gain_decode_is_deterministic_and_positive() {
        // A non-degenerate code vector with two unit pulses (Q9).
        let mut code = [0i16; 64];
        code[3] = 512;
        code[10] = -512;

        let mut mem_a = [0i16; DEC_GAIN_LEN];
        let mut mem_b = [0i16; DEC_GAIN_LEN];
        init_d_gain2(&mut mem_a);
        init_d_gain2(&mut mem_b);

        let a = d_gain2(20, 6, &code, 64, false, false, 0, false, 0, &mut mem_a);
        let b = d_gain2(20, 6, &code, 64, false, false, 0, false, 0, &mut mem_b);
        assert_eq!(a, b);
        assert!(a.0 >= 0, "pitch gain non-negative");
        assert_eq!(mem_a, mem_b, "predictor state evolves deterministically");
        // The predictor energy slot advanced off its -14336 init for a real code.
        assert_ne!(mem_a[0], -14336);
    }
}
