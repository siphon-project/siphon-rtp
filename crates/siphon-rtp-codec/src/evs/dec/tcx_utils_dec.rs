//! TCX decoder helpers (TS 26.442 `lib_dec/tcx_utils_dec.c`; TS 26.445 §6.2.2.3 residual
//! de-quantisation, §6.2.5 memory update).

use crate::evs::cnst::{
    LFAC, L_EXC_MEM_DEC, L_FRAME16K, L_FRAME_PLUS, L_SYN_MEM, M, NPRM_RESQ, TCX_RES_Q_BITS_GAIN,
};
use crate::evs::com::preemph::e_util_f_preemph3;
use crate::evs::com::residu::residu3;
use crate::evs::com::tools::scale_sig;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{GAIN_CORR_FAC, GAIN_CORR_INV_FAC};
use crate::itu::basic_ops::{
    add, l_add, l_mult, l_negate, l_shr, l_sub, mult_r, negate, shl, shr, sub,
};
use crate::itu::stl2009::{lshl, msu_r};

/// `tcx_decoder_memory_update`: output the decoded frame `xn_buf[0..L_frame_glob]` as `synthout`,
/// slide it into the synthesis history `syn` and (not for `fb`) update the pre-emphasised
/// synthesis memories, the excitation memory (the residual of the frame through `a`) and the
/// last LPC filter of the state. `syn` is the state's `syn` (`M + 1` samples).
pub fn tcx_decoder_memory_update(
    xn_buf: &[i16],
    synthout: &mut [i16],
    l_frame_glob: i16,
    a: &[i16],
    st: &mut DecoderState,
    syn: &mut [i16],
    fb: i8,
) {
    const MEMORY: usize = M as usize + 1;
    let mut buf = [0i16; 1 + M as usize + LFAC as usize + L_FRAME_PLUS as usize];
    let frame = l_frame_glob.max(0) as usize;

    let preemph = st.preemph_fac;

    // Output synth
    synthout[..frame].copy_from_slice(&xn_buf[..frame]);

    // Update synth: synth = buf + M + 1
    buf[..MEMORY].copy_from_slice(&syn[..MEMORY]);
    buf[MEMORY..MEMORY + frame].copy_from_slice(&xn_buf[..frame]);
    syn[..MEMORY].copy_from_slice(&buf[MEMORY + frame - MEMORY..MEMORY + frame]);

    if fb == 0 {
        // Emphasis of synth -> synth_pe
        let mut tmp = buf[0]; // synth[-M-1]
        st.q_syn = e_util_f_preemph3(&mut buf[1..], preemph, add(M, l_frame_glob), &mut tmp, 1);
        st.q_syn = st.q_syn.wrapping_sub(1);
        st.prev_q_syn = st.q_syn;
        let m = M as usize;
        st.mem_syn2
            .copy_from_slice(&buf[MEMORY + frame - m..MEMORY + frame]);
        let syn_mem = L_SYN_MEM as usize;
        st.mem_syn_r
            .copy_from_slice(&buf[MEMORY + frame - syn_mem..MEMORY + frame]);

        if st.tcxonly == 0 || sub(l_frame_glob, L_FRAME16K) <= 0 {
            // Update excitation
            let q_syn_plus_1 = i32::from(st.q_syn) + 1;
            if sub(q_syn_plus_1 as i16, st.q_exc) != 0 {
                scale_sig(
                    &mut st.old_exc,
                    L_EXC_MEM_DEC,
                    sub(q_syn_plus_1 as i16, st.q_exc),
                );
            }
            st.q_exc = q_syn_plus_1 as i16;
            st.q_subfr = [st.q_exc; 5];

            // the reference asserts L_frame_glob < L_EXC_MEM_DEC
            let exc_mem = L_EXC_MEM_DEC as usize;
            st.old_exc.copy_within(frame.., 0);
            residu3(
                a,
                &buf,
                MEMORY,
                &mut st.old_exc[exc_mem - frame..],
                l_frame_glob,
                1,
            );
        }

        // Update old_Aq
        st.old_aq_12_8.copy_from_slice(&a[..MEMORY]);
    }
}

/// `tcx_ari_res_invQ_spec`: refine the arithmetic-decoded spectrum `x_q` (Q31 - `x_q_e`) with the
/// residual bits in `prm` (nonzero lines first, then the zeroed lines' sign bits), up to
/// `target_bits` (at most `NPRM_RESQ`), scaling each correction by `x_fac` (Q14). `bits` is the
/// number of bits used so far; returns the number used including them.
pub fn tcx_ari_res_inv_q_spec(
    x_q: &mut [i32],
    x_q_e: i16,
    l_frame: i16,
    prm: &[i16],
    target_bits: i16,
    bits: i16,
    deadzone: i16,
    x_fac: &[i16],
) -> i16 {
    let mut zeros = [0i16; L_FRAME_PLUS as usize];
    let mut num_zeros: i16 = 0;
    let mut bits = bits;

    // Limit the number of residual bits
    let mut target_bits = target_bits.min(NPRM_RESQ);

    // Requantize the spectrum line-by-line
    // fac_m = deadzone * 0.5f;
    for i in 0..l_frame {
        if sub(bits, target_bits) >= 0 {
            // no bits left
            break;
        }

        let line = i as usize;
        if x_q[line] != 0 {
            let mut sign = x_fac[line];
            if x_q[line] < 0 {
                sign = negate(sign);
            }

            // x_Q[i] += sign*(prm[bits++] * 0.5f - fac_m);
            x_q[line] = l_sub(
                x_q[line],
                l_shr(
                    l_mult(sign, add(deadzone, lshl(prm[bits as usize], 15))),
                    x_q_e,
                ),
            );
            bits = add(bits, 1);
        } else {
            zeros[num_zeros as usize] = i;
            num_zeros = add(num_zeros, 1);
        }
    }

    // Requantize zeroed-lines of the spectrum
    let fac_p = msu_r(
        1417339264, /* 0.33f*2.0f Q31 */
        deadzone, 21627, /* 0.33f*2.0f Q15 */
    ); // Q15
    target_bits = sub(target_bits, 1); // reserve 1 bit for the check below

    let s = sub(x_q_e, 1);
    for &zero_line in &zeros[..num_zeros as usize] {
        if sub(bits, target_bits) >= 0 {
            // 1 or 0 bits left
            break;
        }

        let line = zero_line as usize;

        if prm[bits as usize] != 0 {
            bits = add(bits, 1);
            let mut l_tmp = l_mult(fac_p, x_fac[line]); // Q30
            if prm[bits as usize] == 0 {
                l_tmp = l_negate(l_tmp);
            }
            x_q[line] = l_shr(l_tmp, s);
        }
        bits = add(bits, 1);
    }

    bits
}

/// `tcx_res_invQ_gain`: refine the TCX global gain `*gain_tcx` (exponent `*gain_tcx_e`) with the
/// first `min(res_q_bits, TCX_RES_Q_BITS_GAIN)` residual bits of `prm`. Returns the bits used.
pub fn tcx_res_inv_q_gain(
    gain_tcx: &mut i16,
    gain_tcx_e: &mut i16,
    prm: &[i16],
    res_q_bits: i16,
) -> i16 {
    let mut gain = *gain_tcx;

    // make sure we have a bit of headroom
    if sub(gain, 0x7000) > 0 {
        gain = shr(gain, 1);
        *gain_tcx_e = add(*gain_tcx_e, 1);
    }

    // Refine the gain quantization
    let tmp1 = res_q_bits.min(TCX_RES_Q_BITS_GAIN);
    let mut bits: i16 = 0;
    while bits < tmp1 {
        let mut tmp2 = GAIN_CORR_FAC[bits as usize];
        if prm[bits as usize] == 0 {
            tmp2 = GAIN_CORR_INV_FAC[bits as usize];
        }

        gain = mult_r(gain, tmp2);
        if prm[bits as usize] != 0 {
            gain = shl(gain, 1);
        }
        bits += 1;
    }

    *gain_tcx = gain;

    bits
}

/// `tcx_res_invQ_spec`: refine the quantized spectrum `x` (Q31 - `x_e`) with the residual bits in
/// `prm` from index `bits` on (up to `res_q_bits`, at most `NPRM_RESQ`): one bit moves each
/// nonzero line (those whose low-frequency de-emphasis factor allows it, when `lf_deemph_factors`
/// is given) by ±`sq_round` / 2, then sign bits fill zeroed lines. Returns the bits used.
pub fn tcx_res_inv_q_spec(
    x: &mut [i32],
    x_e: i16,
    l_frame: i16,
    prm: &[i16],
    res_q_bits: i16,
    bits: i16,
    sq_round: i16,
    lf_deemph_factors: Option<&[i16]>,
) -> i16 {
    let mut bits = bits;

    // Limit the number of residual bits
    let mut res_q_bits = res_q_bits.min(NPRM_RESQ);

    // Requantize the spectrum line-by-line
    let fac_m = shr(sq_round, 1);
    let fac_p = sub(0x4000, fac_m);

    let mut lf_deemph_factor: i16 = 0x4000;
    let s = sub(x_e, 1);

    for i in 0..l_frame as usize {
        if sub(bits, res_q_bits) >= 0 {
            break;
        }

        if x[i] != 0 && lf_deemph_factors.is_none_or(|factors| sub(factors[i], 0x2000) > 0) {
            if let Some(factors) = lf_deemph_factors {
                lf_deemph_factor = factors[i];
            }

            if prm[bits as usize] == 0 {
                let mut tmp = 0;

                if x[i] > 0 {
                    tmp = l_mult(fac_m, lf_deemph_factor);
                }
                if x[i] < 0 {
                    tmp = l_mult(fac_p, lf_deemph_factor);
                }

                x[i] = l_sub(x[i], l_shr(tmp, s));
            } else {
                let mut tmp = 0;

                if x[i] > 0 {
                    tmp = l_mult(fac_p, lf_deemph_factor);
                }
                if x[i] < 0 {
                    tmp = l_mult(fac_m, lf_deemph_factor);
                }

                x[i] = l_add(x[i], l_shr(tmp, s));
            }
            bits = add(bits, 1);
        }
    }

    // Quantize zeroed-line of the spectrum
    res_q_bits = sub(res_q_bits, 1);

    if let Some(factors) = lf_deemph_factors {
        let c = sub(
            21627, /* 0.66f Q15 */
            mult_r(sq_round, 21627 /* 0.66f Q15 */),
        );

        for i in 0..l_frame as usize {
            if sub(bits, res_q_bits) >= 0 {
                break;
            }

            if x[i] == 0 && sub(factors[i], 0x2000) > 0 {
                if prm[bits as usize] != 0 {
                    bits = add(bits, 1);

                    let mut tmp = l_mult(c, factors[i]);
                    if prm[bits as usize] == 0 {
                        tmp = l_negate(tmp);
                    }

                    x[i] = l_shr(tmp, s);
                }
                bits = add(bits, 1);
            }
        }
    } else {
        for line in &mut x[..l_frame as usize] {
            if sub(bits, res_q_bits) >= 0 {
                break;
            }

            if *line == 0 {
                if prm[bits as usize] != 0 {
                    bits = add(bits, 1);

                    let mut tmp = l_mult(21627 /* 1.32f Q14 */, fac_p);
                    if prm[bits as usize] == 0 {
                        tmp = l_negate(tmp);
                    }

                    *line = l_shr(tmp, s);
                }
                bits = add(bits, 1);
            }
        }
    }

    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gain_refinement_uses_at_most_three_bits() {
        let (mut gain, mut gain_e) = (0x4000i16, 0i16);
        let used = tcx_res_inv_q_gain(&mut gain, &mut gain_e, &[1, 0, 1, 1, 1], 5);
        assert_eq!(used, TCX_RES_Q_BITS_GAIN);
    }

    #[test]
    fn a_residual_bit_moves_a_nonzero_line_towards_its_cell_edge() {
        let mut x = [1 << 20, 0];
        let used = tcx_res_inv_q_spec(&mut x, 0, 1, &[1, 0, 0], 4, 0, 0x2000, None);
        assert_eq!(used, 1);
        assert!(x[0] > 1 << 20);
    }
}
