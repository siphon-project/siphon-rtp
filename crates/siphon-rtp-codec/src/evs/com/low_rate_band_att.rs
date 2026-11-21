//! Fine gain prediction and decoding of the PVQ bands (TS 26.442 `lib_com/low_rate_band_att_fx.c`;
//! TS 26.445 §5.3.4.2.7.3, §6.2.3.2.1.4).

use crate::evs::basop::l_extract_lc;
use crate::evs::cnst::HQ_CORE;
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::math_op::{isqrt_lc, pow2};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    BAND_LEN_ENER_SHIFT, BAND_LEN_IDX, FINEGAIN_FX, FINE_GAIN_PRED_SQRT_BW, INV_TBL_FX,
};
use crate::itu::basic_ops::{
    abs_s, add, div_s, extract_l, l_mult, l_shl, l_shr, mult_r, norm_l, round_word, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, l_mult0, mpy_32_16_ss};

/// `table[index]`, 0 past either end. The decoder's band sizes keep every index inside its table
/// (`band_len_idx` maps each PVQ band width to a row); the fallback only keeps an inconsistent
/// band layout from panicking.
fn at(table: &[i16], index: i16) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .unwrap_or(0)
}

/// `fine_gain_pred_fx`: predict each band's fine gain (Q12) from the energy of its decoded shape
/// `xq` (Q15), zeroing bands that received no pulses. `r` is the C's `R`, which may be NULL.
pub fn fine_gain_pred(
    sfm_start: &[i16],
    sfm_end: &[i16],
    sfm_size: &[i16],
    i_sort: &[i16],
    k_pulses: &[i16],
    maxpulse: &[i16],
    r: Option<&[i16]>,
    num_sfm: i16,
    xq: &mut [i16],
    y: &mut [i16],
    fg_pred: &mut [i16],
    core: i16,
) {
    for band in 0..num_sfm as usize {
        let sorted = i_sort[band] as usize;
        let k = k_pulses[sorted];
        if k > 0 {
            // bw, bw_idx only used if k>0
            let bw = sfm_size[sorted];
            let bw_idx = at(&BAND_LEN_IDX, shr(bw, 3));
            let mut xx: i32 = 0;
            let shift = at(&BAND_LEN_ENER_SHIFT, bw_idx);
            for i in sfm_start[sorted]..sfm_end[sorted] {
                // xx += xq[i] * xq[i];
                let tmp = shr(xq[i as usize], shift); // 15-shift
                xx = l_mac0(xx, tmp, tmp); // 30-2*shift
            }

            if xx > 0 {
                // Normalize synthesis to RMS=1.0: gp = sqrt(bw / xx)
                let mut exp = norm_l(xx);
                let mut l_tmp = l_shl(xx, exp); // 2*(15-shift)+exp
                exp = sub(31, add(exp, sub(30, shl(shift, 1))));
                l_tmp = isqrt_lc(l_tmp, &mut exp); // 31 - exp
                l_tmp = mpy_32_16_ss(l_tmp, at(&FINE_GAIN_PRED_SQRT_BW, bw_idx)).0; // 31-exp+11-15=27-exp
                let mut gp = round_word(l_shl(l_tmp, add(1, exp))); // 27-exp+1+exp-16=12

                if let Some(r) = r {
                    // 256 is 32 in Q3
                    if sub(core, HQ_CORE) == 0 && sub(r[sorted], 256) <= 0 {
                        // accuracy = ((float)k/(float)bw)*maxpulse[i_sort[band]];
                        l_tmp = l_mult(k, at(&INV_TBL_FX, bw)); // 0+15+1
                        let exp2 = norm_l(l_tmp);
                        let mut tmp = round_word(l_shl(l_tmp, exp2)); // 16+exp2-16
                        l_tmp = l_mult0(maxpulse[sorted], tmp); // 0+exp2
                        exp = norm_l(l_tmp);
                        let accuracy = round_word(l_shl(l_tmp, exp)); // exp2+exp-16=exp-16
                        exp = add(exp, exp2);

                        // gp *= 1.0f - 0.05f / accuracy;
                        tmp = div_s(13107, accuracy); // 0.05 in Q18
                        tmp = shr(tmp, sub(34, exp)); // 15+18-exp+16-15=34-exp
                        tmp = sub(32767, tmp);
                        // Limit attenuation to norm quantizer error, 2^-0.25 in Q15
                        tmp = tmp.max(27554);
                        gp = mult_r(tmp, gp); // 15+12+1-16=12
                    }
                }

                fg_pred[band] = gp;
            } else {
                fg_pred[band] = 0;
            }
        } else {
            fg_pred[band] = 0;
            for i in sfm_start[sorted]..sfm_end[sorted] {
                y[i as usize] = 0;
                xq[i as usize] = 0;
            }
        }
    }
}

/// `get_max_pulses_fx`: the largest pulse magnitude of each band of `inp_vector`.
pub fn get_max_pulses(
    band_start: &[i16],
    band_end: &[i16],
    k_sort: &[i16],
    npulses: &[i16],
    bands: i16,
    inp_vector: &[i16],
    maxpulse: &mut [i16],
) {
    for &sorted in k_sort.iter().take(bands.max(0) as usize) {
        let sorted = sorted as usize;
        let npul = npulses[sorted];
        let mut maxp: i16 = 0;
        if npul > 0 {
            for i in band_start[sorted]..band_end[sorted] {
                let tmp = abs_s(inp_vector[i as usize]);
                if sub(tmp, maxp) > 0 {
                    maxp = tmp;
                }
            }
        }
        maxpulse[sorted] = maxp;
    }
}

/// `fine_gain_dec_fx`: read each band's fine-gain correction (`gain_bits[ord[band]]` bits) and
/// apply it to the predicted gain `fg_pred[band]` (Q12).
pub fn fine_gain_dec(
    st: &mut DecoderState,
    ord: &[i16],
    num_sfm: i16,
    gain_bits: &[i16],
    fg_pred: &mut [i16],
) {
    for band in 0..num_sfm as usize {
        let gbits = gain_bits[ord[band] as usize];
        if gbits > 0 && fg_pred[band] != 0 {
            let idx = get_next_indice(st, gbits) as i16;
            // The allocator gives at most 5 bits, the size of `finegain_fx`; a wider field would
            // read past the codebook in the reference.
            let codebook: &[i16] = usize::try_from(gbits - 1)
                .ok()
                .and_then(|row| FINEGAIN_FX.get(row))
                .copied()
                .unwrap_or(&[]);
            let gain_dbq = at(codebook, idx);

            // Update predicted gain with quantized correction
            let mut l_tmp = l_mult0(gain_dbq, 21771); // 21771=0.05*log2(10); 14+17=31
            l_tmp = l_shr(l_tmp, 15);
            let (mut exp1, mut tmp1) = l_extract_lc(l_tmp);
            tmp1 = abs_s(tmp1);
            tmp1 = extract_l(pow2(14, tmp1));
            exp1 = sub(14, exp1);

            l_tmp = l_mult0(fg_pred[band], tmp1); // 12+exp1
            fg_pred[band] = round_word(l_shl(l_tmp, sub(16, exp1))); // 12+exp1+16-exp1-16=12
        }
    }
}
