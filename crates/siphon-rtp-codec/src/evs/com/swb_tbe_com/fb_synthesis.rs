//! FB TBE high-band synthesis: the elliptic band-pass cascade at 48 kHz and the energy matching
//! that follows it (TS 26.442 `lib_com/swb_tbe_com_fx.c`; TS 26.445 §6.1.3.4).

use crate::evs::basop::mult_32_16;
use crate::evs::com::math_op::isqrt_lc;
use crate::evs::com::tools::{scale_sig32, sum2_mod};
use crate::evs::rom::{FULL_BAND_BPF_1_FX, FULL_BAND_BPF_3_FX};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_mult, l_negate, l_shl, l_shr,
    l_sub, mult, negate, norm_l, shl, shr, sub,
};

/// Samples per 20 ms frame at 48 kHz.
const FRAME: usize = 960;
/// The order of each of the three 4th-order sections (the number of history samples).
const HISTORY: usize = 4;
/// Length of a stage buffer: its `HISTORY` samples of history, then one frame.
const STAGE: usize = HISTORY + FRAME;

/// One 4th-order section of the elliptic cascade: `y[i] = (Σ b[k]·x[i - k]) / 8 - 4·Σ a[k]·y[i - k]`
/// for the 960 samples `i`, `x` and `y` carrying `HISTORY` samples of history in front (so output
/// `i` is `y[HISTORY + i]`). The first four outputs add their feed-forward terms before the
/// feedback ones, the others interleave them, exactly as the reference's unrolled head and loop do
/// (the order matters when a 32-bit sum saturates). `ff(index, coefficient)` is the feed-forward
/// product, `L_mult` for 16-bit input and `Mult_32_16` for 32-bit; `y_max` tracks `max |y|`.
fn bpf_section(
    ff: &dyn Fn(usize, i16) -> i32,
    y: &mut [i32; STAGE],
    b: &[i16; 5],
    a: &[i16; 5],
    mut y_max: Option<&mut i32>,
) {
    for i in 0..FRAME {
        let p = i + HISTORY;
        let ff_term = |index: usize, coefficient: usize| l_shr(ff(index, b[coefficient]), 3);
        let fb_term = |lag: usize| l_shl(mult_32_16(y[p - lag], a[lag]), 2);

        let mut t = ff_term(p - 4, 4);
        if i < HISTORY {
            t = l_add(ff_term(p - 3, 3), t);
            t = l_add(ff_term(p - 2, 2), t);
            t = l_add(ff_term(p - 1, 1), t);
            t = l_add(ff_term(p, 0), t);
            t = l_sub(t, fb_term(1));
            t = l_sub(t, fb_term(2));
            t = l_sub(t, fb_term(3));
        } else {
            t = l_add(ff_term(p - 3, 3), t);
            t = l_sub(t, fb_term(1));
            t = l_add(ff_term(p - 2, 2), t);
            t = l_sub(t, fb_term(2));
            t = l_add(ff_term(p - 1, 1), t);
            t = l_sub(t, fb_term(3));
            t = l_add(ff_term(p, 0), t);
        }
        let value = l_sub(t, fb_term(4));
        y[p] = value;
        if let Some(max) = y_max.as_deref_mut() {
            *max = if i == 0 {
                l_abs(value)
            } else {
                (*max).max(l_abs(value))
            };
        }
    }
}

/// `elliptic_bpf_48k_generic_fx`: the three-section elliptic band-pass of the FB high band on the
/// 48 kHz input `input_fx[0..960]` (Q`q_input_fx`), into `output_fx`. `memory_fx2` holds the four
/// samples of history of each section's input and output and `memory_fx_q` their Q; `q_input_fx`
/// receives the output's Q.
pub fn elliptic_bpf_48k_generic(
    input_fx: &[i16],
    q_input_fx: &mut i16,
    output_fx: &mut [i16],
    memory_fx2: &mut [[i32; 4]; 4],
    memory_fx_q: &mut [i16],
    full_band_bpf_fx: &[[i16; 5]; 6],
) {
    let mut x1 = [0i16; STAGE];
    let mut y1 = [0i32; STAGE];
    let mut y2 = [0i32; STAGE];
    let mut y3 = [0i32; STAGE];
    let mut memory2_fx_1 = [0i32; 4];
    let mut memory2_fx_2 = [0i32; 4];
    let mut memory2_fx_3 = [0i32; 4];

    for i in 0..4 {
        let memory_fx0 = extract_l(memory_fx2[0][i]);
        x1[i] = shl(memory_fx0, sub(*q_input_fx, memory_fx_q[0]));
        memory2_fx_1[i] = l_shl(memory_fx2[1][i], sub(add(*q_input_fx, 11), memory_fx_q[1]));
        memory2_fx_2[i] = l_shl(memory_fx2[2][i], sub(add(*q_input_fx, 6), memory_fx_q[2]));
        memory2_fx_3[i] = l_shl(memory_fx2[3][i], sub(add(*q_input_fx, 1), memory_fx_q[3]));
    }
    x1[HISTORY..].copy_from_slice(&input_fx[..FRAME]);

    // section 1: 16-bit input, history in `memory2_fx_1`
    y1[..HISTORY].copy_from_slice(&memory2_fx_1);
    bpf_section(
        &|index, coefficient| l_mult(x1[index], coefficient),
        &mut y1,
        &full_band_bpf_fx[0],
        &full_band_bpf_fx[3],
        None,
    );

    memory_fx2[0][0] = i32::from(input_fx[FRAME - 4]);
    memory_fx2[0][1] = i32::from(input_fx[FRAME - 3]);
    memory_fx2[0][2] = i32::from(input_fx[FRAME - 2]);
    memory_fx2[0][3] = i32::from(input_fx[FRAME - 1]);

    // section 2: the first section's output (with its history in front) is the input
    let mut x2 = y1;
    x2[..HISTORY].copy_from_slice(&memory2_fx_1);
    y2[..HISTORY].copy_from_slice(&memory2_fx_2);
    let mut l_tmp_max: i32 = 0;
    bpf_section(
        &|index, coefficient| mult_32_16(x2[index], coefficient),
        &mut y2,
        &full_band_bpf_fx[1],
        &full_band_bpf_fx[4],
        Some(&mut l_tmp_max),
    );

    let q_temp = sub(norm_l(l_tmp_max), 4);
    scale_sig32(&mut y2[HISTORY..], FRAME as i16, q_temp);

    memory_fx2[1][0] = y1[HISTORY + FRAME - 4];
    memory_fx2[1][1] = y1[HISTORY + FRAME - 3];
    memory_fx2[1][2] = y1[HISTORY + FRAME - 2];
    memory_fx2[1][3] = y1[HISTORY + FRAME - 1];

    // section 3: history rescaled to the scaled second-section output
    for j in 0..4 {
        memory2_fx_2[j] = l_shl(
            memory_fx2[2][j],
            sub(add(add(*q_input_fx, 6), q_temp), memory_fx_q[2]),
        );
        memory2_fx_3[j] = l_shl(
            memory_fx2[3][j],
            sub(add(add(*q_input_fx, 1), q_temp), memory_fx_q[3]),
        );
    }
    let mut x3 = y2;
    x3[..HISTORY].copy_from_slice(&memory2_fx_2);
    y3[..HISTORY].copy_from_slice(&memory2_fx_3);
    bpf_section(
        &|index, coefficient| mult_32_16(x3[index], coefficient),
        &mut y3,
        &full_band_bpf_fx[2],
        &full_band_bpf_fx[5],
        Some(&mut l_tmp_max),
    );

    memory_fx2[2][0] = y2[HISTORY + FRAME - 4];
    memory_fx2[2][1] = y2[HISTORY + FRAME - 3];
    memory_fx2[2][2] = y2[HISTORY + FRAME - 2];
    memory_fx2[2][3] = y2[HISTORY + FRAME - 1];
    memory_fx2[3][0] = y3[HISTORY + FRAME - 4];
    memory_fx2[3][1] = y3[HISTORY + FRAME - 3];
    memory_fx2[3][2] = y3[HISTORY + FRAME - 2];
    memory_fx2[3][3] = y3[HISTORY + FRAME - 1];

    memory_fx_q[0] = *q_input_fx;
    memory_fx_q[1] = add(*q_input_fx, 11);
    memory_fx_q[2] = add(add(*q_input_fx, 6), q_temp);
    memory_fx_q[3] = add(add(*q_input_fx, 1), q_temp);

    let q_temp2 = norm_l(l_tmp_max);
    scale_sig32(&mut y3[HISTORY..], FRAME as i16, q_temp2);
    for i in 0..FRAME {
        output_fx[i] = extract_h(y3[HISTORY + i]);
    }
    *q_input_fx = sub(add(add(*q_input_fx, q_temp), q_temp2), 15);
}

/// `synthesise_fb_high_band_fx`: the FB high band (14 to 20 kHz) at 48 kHz from the 320-sample FB
/// excitation (Q`q_fb_exc`): upsamples it by zero-stuffing, band-passes it, and scales it to the
/// energy `fb_exc_energy` times the ratio `ratio` into `output` (Q`qout`). `prev_fbbwe_ratio`
/// keeps the ratio for the next frame (halved after a bad frame).
pub fn synthesise_fb_high_band(
    excitation_in: &[i16],
    q_fb_exc: i16,
    output: &mut [i16],
    fb_exc_energy: i32,
    ratio: i16,
    l_frame: i16,
    bfi: i16,
    prev_fbbwe_ratio: &mut i16,
    bpf_memory: &mut [[i32; 4]; 4],
    bpf_memory_q: &mut [i16],
    qout: i16,
) {
    let mut excitation_in_interp3 = [0i16; FRAME];
    let mut tmp = [0i16; FRAME];

    for (j, i) in (0..FRAME).step_by(3).enumerate() {
        excitation_in_interp3[i] = mult(excitation_in[j], 24576);
        excitation_in_interp3[i + 1] = 0;
        excitation_in_interp3[i + 2] = 0;
    }

    let mut exp_tmp = sub(q_fb_exc, 2);
    let bpf = if sub(l_frame, 320) == 0 {
        &FULL_BAND_BPF_3_FX
    } else {
        &FULL_BAND_BPF_1_FX
    };
    elliptic_bpf_48k_generic(
        &excitation_in_interp3,
        &mut exp_tmp,
        &mut tmp,
        bpf_memory,
        bpf_memory_q,
        bpf,
    );

    let temp1 = sum2_mod(&tmp, FRAME as i16);
    let mut l_tmp = fb_exc_energy.max(1);
    let mut exp = norm_l(l_tmp);
    let mut tmp3 = extract_h(l_shl(l_tmp, exp));
    let tmp1 = sub(add(q_fb_exc, q_fb_exc), 8);
    exp = sub(sub(31, tmp1), exp);

    let mut exp2 = norm_l(temp1);
    let mut tmp2 = extract_h(l_shl(temp1, exp2));
    exp2 = sub(sub(31, sub(shl(exp_tmp, 1), 8)), exp2);

    exp = sub(exp2, exp);
    if sub(tmp2, tmp3) > 0 {
        tmp2 = shr(tmp2, 1);
        exp = add(exp, 1);
    }

    let ratio2 = if tmp3 != 0 {
        tmp3 = div_s(tmp2, tmp3);
        l_tmp = l_deposit_h(tmp3);
        l_tmp = isqrt_lc(l_tmp, &mut exp);
        mult_32_16(l_tmp, ratio)
    } else {
        0
    };

    if bfi == 0 {
        *prev_fbbwe_ratio = ratio;
    } else {
        *prev_fbbwe_ratio = shr(ratio, 1);
    }

    let tmp3 = add(sub(qout, add(sub(1, exp), exp_tmp)), 16);
    for i in 0..FRAME {
        let l_tmp = mult_32_16(ratio2, tmp[i]);
        if l_tmp < 0 {
            output[i] = negate(extract_h(l_shl(l_negate(l_tmp), tmp3)));
        } else {
            output[i] = extract_h(l_shl(l_tmp, tmp3));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_band_pass_of_silence_is_silence() {
        let input = [0i16; FRAME];
        let mut output = [1i16; FRAME];
        let mut memory = [[0i32; 4]; 4];
        let mut memory_q = [0i16; 4];
        let mut q_input = 5;
        elliptic_bpf_48k_generic(
            &input,
            &mut q_input,
            &mut output,
            &mut memory,
            &mut memory_q,
            &FULL_BAND_BPF_1_FX,
        );
        assert_eq!(output, [0; FRAME]);
        assert_eq!(memory, [[0; 4]; 4]);
    }

    #[test]
    fn synthesis_of_a_silent_excitation_is_silent_and_remembers_the_ratio() {
        let excitation = [0i16; 320];
        let mut output = [1i16; FRAME];
        let mut memory = [[0i32; 4]; 4];
        let mut memory_q = [0i16; 4];
        let mut prev_ratio = 0;
        synthesise_fb_high_band(
            &excitation,
            10,
            &mut output,
            0,
            20000,
            320,
            1,
            &mut prev_ratio,
            &mut memory,
            &mut memory_q,
            4,
        );
        assert_eq!(output, [0; FRAME]);
        assert_eq!(prev_ratio, 10000);
    }
}
