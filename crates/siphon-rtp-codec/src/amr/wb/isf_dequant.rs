//! AMR-WB 36-bit ISF dequantization (3GPP TS 26.173 `qpisf_2s.c`), ported bit-exact.
//!
//! The 7.5 kbit/s modes quantize the ISF residual with a 2-stage split VQ (5 indices): a first
//! stage over two sub-vectors (`dico1`/`dico2`) and a second stage over three (`dico21`/`dico22`/
//! `dico23`). [`dpisf_2s_36b`] sums the looked-up vectors, adds the mean and the MA-predicted
//! residual, updates the predictor state, and reorders to enforce a minimum ISF spacing. A bad
//! frame (`bfi`) is concealed from the running ISF mean and the previous frame.

use super::isf_tables::{
    DICO1_ISF, DICO21_ISF_36B, DICO21_ISF_46B, DICO22_ISF_36B, DICO22_ISF_46B, DICO23_ISF_36B,
    DICO23_ISF_46B, DICO24_ISF_46B, DICO25_ISF_46B, DICO2_ISF, MEAN_ISF,
};
use crate::amr::basic_ops::{add, l_mac, l_mult, mult, round_word, shr, sub};
use crate::amr::wb::constants::M;

/// LPC order (== M for AMR-WB).
const ORDER: usize = M;
/// MA prediction factor, 1/3 in Q15.
const MU: i16 = 10923;
/// Concealment lean toward the previous ISF (0.9, Q15) and its complement.
const ALPHA: i16 = 29491;
const ONE_ALPHA: i16 = 3277; // 32768 - ALPHA
/// Minimum ISF distance, Q15.
const ISF_GAP: i16 = 128;
/// ISF mean-buffer depth.
const L_MEANBUF: usize = 3;

/// Enforce a minimum distance between consecutive ISFs (`Reorder_isf`).
pub fn reorder_isf(isf: &mut [i16], min_dist: i16, n: usize) {
    let mut isf_min = min_dist;
    for value in isf.iter_mut().take(n - 1) {
        if sub(*value, isf_min) < 0 {
            *value = isf_min;
        }
        isf_min = add(*value, min_dist);
    }
}

/// Dequantize the five 36-bit ISF indices into `isf_q` (Q15, in 0..0.5).
///
/// `past_isfq` (the MA predictor residual, `M`) and `isf_buf` (`L_MEANBUF·M`, the running ISF
/// history) are updated; `isfold` is the previous quantized ISF (concealment input). `enc_dec`
/// (true on the decoder) refreshes `isf_buf`; `bfi` selects the concealment path.
#[allow(clippy::too_many_arguments)]
pub fn dpisf_2s_36b(
    indice: &[i16],
    isf_q: &mut [i16],
    past_isfq: &mut [i16],
    isfold: &[i16],
    isf_buf: &mut [i16],
    bfi: bool,
    enc_dec: bool,
) {
    if !bfi {
        // Stage 1: two sub-vectors.
        let d1 = indice[0] as usize * 9;
        isf_q[..9].copy_from_slice(&DICO1_ISF[d1..d1 + 9]);
        let d2 = indice[1] as usize * 7;
        isf_q[9..16].copy_from_slice(&DICO2_ISF[d2..d2 + 7]);

        // Stage 2: three sub-vectors added on top.
        let d21 = indice[2] as usize * 5;
        for i in 0..5 {
            isf_q[i] = add(isf_q[i], DICO21_ISF_36B[d21 + i]);
        }
        let d22 = indice[3] as usize * 4;
        for i in 0..4 {
            isf_q[i + 5] = add(isf_q[i + 5], DICO22_ISF_36B[d22 + i]);
        }
        let d23 = indice[4] as usize * 7;
        for i in 0..7 {
            isf_q[i + 9] = add(isf_q[i + 9], DICO23_ISF_36B[d23 + i]);
        }

        // Add the mean + the MA-predicted residual; update the predictor.
        for i in 0..ORDER {
            let tmp = isf_q[i];
            isf_q[i] = add(tmp, MEAN_ISF[i]);
            isf_q[i] = add(isf_q[i], mult(MU, past_isfq[i]));
            past_isfq[i] = tmp;
        }

        if enc_dec {
            for i in 0..M {
                for j in (1..L_MEANBUF).rev() {
                    isf_buf[j * M + i] = isf_buf[(j - 1) * M + i];
                }
                isf_buf[i] = isf_q[i];
            }
        }
    } else {
        conceal_isf(isf_q, past_isfq, isfold, isf_buf);
    }

    reorder_isf(isf_q, ISF_GAP, ORDER);
}

/// Dequantize the seven 46-bit ISF indices into `isf_q` (Q15, 0..0.5) for the higher modes
/// (`qpisf_2s.c` `Dpisf_2s_46b`). Stage 1 reuses `dico1`/`dico2`; stage 2 splits the first 9 ISFs
/// into three sub-vectors (`dico21/22/23`, dims 3) and the last 7 into two (`dico24` dim 3 + `dico25`
/// dim 4). The mean + MA-predictor update, `enc_dec` ISF-buffer refresh, concealment path and final
/// reorder are byte-identical to the 36-bit decoder.
#[allow(clippy::too_many_arguments)]
pub fn dpisf_2s_46b(
    indice: &[i16],
    isf_q: &mut [i16],
    past_isfq: &mut [i16],
    isfold: &[i16],
    isf_buf: &mut [i16],
    bfi: bool,
    enc_dec: bool,
) {
    if !bfi {
        // Stage 1: two sub-vectors.
        let d1 = indice[0] as usize * 9;
        isf_q[..9].copy_from_slice(&DICO1_ISF[d1..d1 + 9]);
        let d2 = indice[1] as usize * 7;
        isf_q[9..16].copy_from_slice(&DICO2_ISF[d2..d2 + 7]);

        // Stage 2: five sub-vectors added on top (dims 3,3,3,3,4).
        let d21 = indice[2] as usize * 3;
        for i in 0..3 {
            isf_q[i] = add(isf_q[i], DICO21_ISF_46B[d21 + i]);
        }
        let d22 = indice[3] as usize * 3;
        for i in 0..3 {
            isf_q[i + 3] = add(isf_q[i + 3], DICO22_ISF_46B[d22 + i]);
        }
        let d23 = indice[4] as usize * 3;
        for i in 0..3 {
            isf_q[i + 6] = add(isf_q[i + 6], DICO23_ISF_46B[d23 + i]);
        }
        let d24 = indice[5] as usize * 3;
        for i in 0..3 {
            isf_q[i + 9] = add(isf_q[i + 9], DICO24_ISF_46B[d24 + i]);
        }
        let d25 = indice[6] as usize * 4;
        for i in 0..4 {
            isf_q[i + 12] = add(isf_q[i + 12], DICO25_ISF_46B[d25 + i]);
        }

        // Add the mean + the MA-predicted residual; update the predictor.
        for i in 0..ORDER {
            let tmp = isf_q[i];
            isf_q[i] = add(tmp, MEAN_ISF[i]);
            isf_q[i] = add(isf_q[i], mult(MU, past_isfq[i]));
            past_isfq[i] = tmp;
        }

        if enc_dec {
            for i in 0..M {
                for j in (1..L_MEANBUF).rev() {
                    isf_buf[j * M + i] = isf_buf[(j - 1) * M + i];
                }
                isf_buf[i] = isf_q[i];
            }
        }
    } else {
        conceal_isf(isf_q, past_isfq, isfold, isf_buf);
    }

    reorder_isf(isf_q, ISF_GAP, ORDER);
}

/// Bad-frame ISF concealment shared by the 36-bit and 46-bit decoders (`Dpisf_2s_*b` bfi branch):
/// lean the previous quantized ISF toward the running ISF mean and re-estimate the predictor.
fn conceal_isf(isf_q: &mut [i16], past_isfq: &mut [i16], isfold: &[i16], isf_buf: &[i16]) {
    let mut ref_isf = [0i16; M];
    for (i, slot) in ref_isf.iter_mut().enumerate() {
        let mut l_tmp = l_mult(MEAN_ISF[i], 8192);
        for j in 0..L_MEANBUF {
            l_tmp = l_mac(l_tmp, isf_buf[j * M + i], 8192);
        }
        *slot = round_word(l_tmp);
    }
    for i in 0..ORDER {
        isf_q[i] = add(mult(ALPHA, isfold[i]), mult(ONE_ALPHA, ref_isf[i]));
    }
    for i in 0..ORDER {
        let tmp = add(ref_isf[i], mult(past_isfq[i], MU));
        past_isfq[i] = sub(isf_q[i], tmp);
        past_isfq[i] = shr(past_isfq[i], 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorder_enforces_minimum_spacing() {
        let mut isf = [100, 150, 90, 5000, 5050, 0, 0, 0];
        reorder_isf(&mut isf, ISF_GAP, 8);
        // Each ISF is at least ISF_GAP above the previous (or bumped up to meet it).
        for pair in isf[..7].windows(2) {
            assert!(pair[1] - pair[0] >= ISF_GAP || pair[1] >= pair[0], "{pair:?}");
        }
        assert_eq!(isf[0], 128); // 100 < 128 → bumped
        assert_eq!(isf[1], 256); // 150 < 128+128 → bumped
    }

    #[test]
    fn dequant_produces_ordered_spaced_isfs() {
        let mut isf_q = [0i16; M];
        let mut past = [0i16; M];
        let mut buf = [0i16; L_MEANBUF * M];
        dpisf_2s_36b(&[0, 0, 0, 0, 0], &mut isf_q, &mut past, &[0; M], &mut buf, false, true);
        // Reorder spaces the first ORDER-1 ISFs (the last is left as decoded, per spec).
        for pair in isf_q[..ORDER - 1].windows(2) {
            assert!(pair[1] - pair[0] >= ISF_GAP, "ordered+spaced: {pair:?}");
        }
        assert!(isf_q[0] > 0, "first ISF positive");
        // The predictor state was updated (past_isfq holds the pre-mean residual).
        assert!(past.iter().any(|&v| v != 0));
    }

    #[test]
    fn dequant_46b_produces_ordered_spaced_isfs() {
        let mut isf_q = [0i16; M];
        let mut past = [0i16; M];
        let mut buf = [0i16; L_MEANBUF * M];
        dpisf_2s_46b(
            &[0, 0, 0, 0, 0, 0, 0],
            &mut isf_q,
            &mut past,
            &[0; M],
            &mut buf,
            false,
            true,
        );
        for pair in isf_q[..ORDER - 1].windows(2) {
            assert!(pair[1] - pair[0] >= ISF_GAP, "ordered+spaced: {pair:?}");
        }
        assert!(isf_q[0] > 0, "first ISF positive");
        assert!(past.iter().any(|&v| v != 0));
    }

    #[test]
    fn dequant_46b_concealment_is_bounded() {
        // bfi path leans toward the running mean; output stays ordered and finite.
        let mut isf_q = [0i16; M];
        let mut past = [0i16; M];
        let isfold: [i16; M] = [
            500, 1100, 1900, 2800, 3900, 5100, 6400, 7800, 9200, 10500, 11700, 12700, 13500, 14100,
            14600, 7000,
        ];
        let mut buf = [0i16; L_MEANBUF * M];
        for row in buf.chunks_exact_mut(M) {
            row.copy_from_slice(&isfold);
        }
        dpisf_2s_46b(&[0; 7], &mut isf_q, &mut past, &isfold, &mut buf, true, true);
        for pair in isf_q[..ORDER - 1].windows(2) {
            assert!(pair[1] - pair[0] >= ISF_GAP, "concealed ISFs spaced: {pair:?}");
        }
    }

    #[test]
    fn dequant_is_deterministic() {
        let run = |indice: &[i16]| {
            let mut isf_q = [0i16; M];
            let mut past = [0i16; M];
            let mut buf = [0i16; L_MEANBUF * M];
            dpisf_2s_36b(indice, &mut isf_q, &mut past, &[0; M], &mut buf, false, true);
            isf_q
        };
        assert_eq!(run(&[12, 7, 30, 5, 40]), run(&[12, 7, 30, 5, 40]));
    }
}
