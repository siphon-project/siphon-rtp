//! Noise-excited linear prediction (NELP) gain dequantisation and excitation generation, shared
//! by the encoder and decoder (TS 26.442 `lib_com/nelp_fx.c`; TS 26.445 §5.4.4 / §6.1.2.4).

use crate::evs::basop::l_extract_lc;
use crate::evs::cnst::{NB, SWB, WB};
use crate::evs::com::math_op::pow2;
use crate::evs::rom::{
    UVG1CB_NB_FX, UVG1CB_WB_FX, UVG2CB1_NB_FX, UVG2CB1_WB_FX, UVG2CB2_NB_FX, UVG2CB2_WB_FX,
};
use crate::itu::basic_ops::{
    abs_s, extract_l, l_add, l_mult, l_shl, l_shr_r, mult_r, round_word, sub,
};
use crate::itu::stl2009::l_mult0;

/// The three NELP gain codebooks of one bandwidth: the log gains, and the two shape halves.
type UvgCodebooks = (
    &'static [[i16; 2]],
    &'static [[i16; 5]],
    &'static [[i16; 5]],
);

/// A row of a codebook by a bit-stream index: the 5- and 6-bit indices the decoder reads always
/// fit, and a corrupted state index is clamped to the last row instead of read past the table.
fn row<const N: usize>(table: &[[i16; N]], index: i16) -> &[i16; N] {
    let last = table.len().saturating_sub(1);
    &table[(index.max(0) as usize).min(last)]
}

/// `dequantize_uvg_fx`: the ten sub-frame gains `G` of an unvoiced/NELP frame from the index
/// `i_g1` of the two-dimensional log-gain codebook and the indices `i_g2` of the two
/// five-dimensional shape codebooks. With `do_scale`, a frame whose log gains are both below 1
/// keeps three more bits (returned as the gains' Q); otherwise the gains are Q0 and 0 returns.
///
/// The codebooks exist for NB and WB/SWB only; for any other `bwidth` the reference dereferences
/// a null table, and here `G` is left as it is and 0 returned.
pub fn dequantize_uvg(i_g1: i16, i_g2: &[i16], g: &mut [i16], bwidth: i16, do_scale: i16) -> i16 {
    let (uvg1cb, uvg2cb1, uvg2cb2): UvgCodebooks = if sub(bwidth, NB) == 0 {
        (&UVG1CB_NB_FX, &UVG2CB1_NB_FX, &UVG2CB2_NB_FX)
    } else if sub(bwidth, WB) == 0 || sub(bwidth, SWB) == 0 {
        (&UVG1CB_WB_FX, &UVG2CB1_WB_FX, &UVG2CB2_WB_FX)
    } else {
        return 0;
    };
    let g1 = row(uvg1cb, i_g1);

    let mut q_gain: i16 = 0;
    let sc: i16 = if do_scale == 0 {
        11
    } else if sub(g1[0], 4096) < 0 && sub(g1[1], 4096) < 0 {
        // if x < 1, where 10^x is used for gain computation
        q_gain = 3;
        8
    } else {
        11
    };

    for i in 0..2 {
        let shape = if i == 0 {
            row(uvg2cb1, i_g2[0])
        } else {
            row(uvg2cb2, i_g2[1])
        };
        for k in 0..5 {
            // pow(10.0, UVG1CB[iG1][i]) = pow(2.0, UVG1CB[iG1][i]*3.321928)
            let mut l_tmp = l_mult(g1[i], 27213); // Q(13+13+1)->Q27
            l_tmp = l_shr_r(l_tmp, 11); // Q16
            let (exp, frac) = l_extract_lc(l_tmp);
            let frac = extract_l(pow2(14, frac));
            g[i * 5 + k] = round_word(l_shl(l_mult(frac, shape[k]), exp.wrapping_sub(sc)));
            // Q0
        }
    }
    q_gain
}

/// `generate_nelp_excitation_fx`: a 256-sample sparse random excitation, ten segments of 25
/// samples (the last 31) of which only the 6 (8) largest of a linear-congruential noise survive,
/// scaled by the segment's gain `gains[i]` and `gain_fac` (Q14); `seed` advances per sample.
pub fn generate_nelp_excitation(seed: &mut i16, gains: &[i16], output: &mut [i16], gain_fac: i16) {
    let mut tmp = [0i16; 31];
    let mut tmp1 = [0i16; 31];
    let mut index = [0usize; 31];

    for i in 0..10usize {
        let (len, cnt) = if i == 9 { (31usize, 8usize) } else { (25, 6) };

        for j in 0..len {
            let l32 = l_mult0(*seed, 0x0209); // L32 = *seed*521;
            let l16 = extract_l(l_add(l32, 259));
            *seed = l16; // Q0
            tmp[j] = *seed; // Q15, tmp[j]=*seed/32768
            tmp1[j] = abs_s(tmp[j]);
            index[j] = j;
        }

        for k1 in 0..len - 1 {
            for k2 in k1 + 1..len {
                if sub(tmp1[k2], tmp1[k1]) > 0 {
                    let tmpi = index[k2];
                    let tmpf = tmp1[k2];
                    tmp1[k2] = tmp1[k1];
                    index[k2] = index[k1];
                    tmp1[k1] = tmpf;
                    index[k1] = tmpi;
                }
            }
        }

        // using a factor of 1.37 to compensate for the ~ 2.5 ( or 2.73) dB diff between this
        // scheme and EVS-UV
        for j in 0..cnt {
            let mut l16 = mult_r(tmp[index[j]], gain_fac); // Q14
            l16 = mult_r(l16, 0x6EDA); // Q13
            output[i * 25 + index[j]] = round_word(l_shl(l_mult(l16, gains[i]), 2));
            // Q_exc
        }
        for &position in &index[cnt..len] {
            output[i * 25 + position] = 0;
        }
    }
}
