//! PVQ core decoding of the HQ / GSC spectra (TS 26.442 `lib_dec/pvq_core_dec_fx.c`; TS 26.445
//! §6.2.2.3.4): the range-coded band splits, their split energies (angle-coded), the pulse vectors
//! of every part and the fine gains.

use crate::evs::cnst::{MAX_SPLITS, NB_SFM, NB_SFM_MAX, RC_BITS_RESERVED};
use crate::evs::com::basop_util::get_sqrt_word32;
use crate::evs::com::fine_gain_bits::assign_gain_bits;
use crate::evs::com::low_rate_band_att::{fine_gain_dec, fine_gain_pred, get_max_pulses};
use crate::evs::com::math_op::i_mult2;
use crate::evs::com::pvq_com::{
    apply_gain, atan2, band_bits_adjustment, conservative_l1_norm, density_angle2_rms_proj_dec,
    near_opp_split_adjustment, obtain_energy_quantizer_density, shrt_c_div_signed_approx,
    srt_vec_ind16,
};
use crate::evs::com::range_com::range_coder_finalization_f_bits;
use crate::evs::com::tools::{ratio, set16};
use crate::evs::dec::pvq_decode::pvq_decode;
use crate::evs::dec::range_dec::{
    rc_dec_bits, rc_dec_finish, rc_dec_init, rc_dec_update, rc_decode,
};
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{LIM_NEG_INV_TBL_FX, SQRT_DIM_FX};
use crate::itu::basic_ops::{
    add, extract_h, extract_l, l_add, l_mac, l_mult, l_shl, l_shr, l_sub, mult_r, negate, shl, shr,
    sub,
};
use crate::itu::stl2009::{l_mac0, l_msu0, l_mult0, mpy_32_16_ss};

/// `L_FRAME48k`: the largest spectrum the pulse vector holds.
const L_FRAME48K: usize = 960;
/// `MAX_SPLITS` as an index.
const SPLITS: usize = MAX_SPLITS as usize;
/// `THR_ADD_SPLIT`: threshold (bits per coefficient) for an additional split.
const THR_ADD_SPLIT: i32 = 7;

/// `SQRT_DIM_fx[n]`, 0 past the table (a band dimension the decoder never forms).
fn sqrt_dim(n: i16) -> i32 {
    usize::try_from(n)
        .ok()
        .and_then(|n| SQRT_DIM_FX.get(n))
        .copied()
        .unwrap_or(0)
}

/// `Mpy_32_16_ss` with the 48-bit product's high 32 bits and low 16 bits folded back into one
/// Word32 (`L_or(L_shl(acc, 16), L_and(lsb, 0xffff))`), as the reference does it, saturating
/// shift included.
fn mpy_fold(acc: i32, x: i16) -> i32 {
    let (acc, lsb) = mpy_32_16_ss(acc, x);
    l_shl(acc, 16) | i32::from(lsb)
}

/// `pvq_decode_band_fx`: decode one band of `sfmsize` coefficients with `band_bits` (Q3): its
/// split count, the split energies, and each part's pulses and gain-scaled vector.
fn pvq_decode_band(
    st: &mut DecoderState,
    pulse_vector: &mut [i16],
    npulses: &mut i16,
    coefs_quant: &mut [i16],
    sfmsize: i16,
    band_bits: i16,
    bits_left: &mut i16,
    strict_bits: i16,
) {
    let mut part_start = [0i16; SPLITS + 1];
    let mut dim_part = [0i16; SPLITS + 1];
    let mut bits_part = [0i16; SPLITS + 1];
    let mut g_part = [0i16; SPLITS];
    let mut g_part_neg = [0i16; SPLITS];
    let mut sg_part = [0i16; SPLITS + 1];
    let mut idx_sort = [0i16; SPLITS + 1];

    let mut split_bit: i16 = 0;
    let np = get_pvq_splits(st, band_bits, sfmsize, &mut split_bit);
    let band_bits_tot = sub(band_bits, split_bit);
    // get_pvq_splits bounds np to 1..=MAX_SPLITS
    let n = np as usize;

    let dim_parts = extract_h(l_mult(negate(sfmsize), LIM_NEG_INV_TBL_FX[n]));
    set16(&mut dim_part, dim_parts, sub(np, 1));
    dim_part[n - 1] = sub(sfmsize, i_mult2(dim_parts, sub(np, 1)));

    part_start[0] = 0;
    for j in 1..n {
        part_start[j] = add(part_start[j - 1], dim_part[j - 1]);
    }

    // Decode the energies.
    set16(&mut g_part_neg, -32768, np);
    if sub(np, 1) > 0 {
        decode_energies(
            st,
            np,
            &dim_part,
            &mut bits_part,
            &mut g_part_neg,
            band_bits_tot,
            bits_left,
            sfmsize,
            strict_bits,
        );
    } else {
        bits_part[0] = band_bits_tot;
    }

    let mut pool_tot: i16 = 0;

    for j in 0..n {
        g_part[j] = negate(g_part_neg[j]);
    }

    srt_vec_ind16(&g_part, &mut sg_part, &mut idx_sort, np);
    for j in 0..n {
        let js = idx_sort[n - 1 - j] as usize;
        let pool_part = shrt_c_div_signed_approx(pool_tot, sub(np, j as i16));
        bits_part[js] = add(bits_part[js], pool_part).clamp(0, 256);

        let norm = conservative_l1_norm(
            dim_part[js],
            bits_part[js],
            strict_bits,
            *bits_left,
            pool_tot,
            *npulses,
        );
        let k_val = norm.dvec;
        *bits_left = norm.qspare;
        pool_tot = norm.qreservplus;
        *npulses = norm.dspecplus;

        let start = part_start[js].max(0) as usize;
        if k_val > 0 {
            pvq_decode(
                st,
                &mut coefs_quant[start..],
                &mut pulse_vector[start..],
                k_val,
                dim_part[js],
                g_part_neg[js],
            );
        } else {
            set16(&mut coefs_quant[start..], 0, dim_part[js]);
            set16(&mut pulse_vector[start..], 0, dim_part[js]);
        }
    }
}

/// `pvq_decode_frame_fx`: range-decode the pulse vectors (`pulse_vector`) and their gain-scaled
/// versions (`coefs_quant`, Q15 per band) of every band with a bit allocation `r` (Q3), with
/// `pvq_bits` bits for the whole frame; `npulses` receives each band's pulse count.
pub fn pvq_decode_frame(
    st: &mut DecoderState,
    coefs_quant: &mut [i16],
    npulses: &mut [i16],
    pulse_vector: &mut [i16],
    sfm_start: &[i16],
    sfm_end: &[i16],
    sfmsize: &[i16],
    nb_sfm: i16,
    r: &[i16],
    pvq_bits: i16,
    core: i16,
) {
    let mut bit_pool: i16 = 0;
    let mut r_sort = [0i16; NB_SFM as usize];
    let mut i_sort = [0i16; NB_SFM as usize];
    // The reference's sort buffers hold NB_SFM bands; no caller passes more.
    let bands = (nb_sfm.max(0) as usize).min(NB_SFM as usize);

    rc_dec_init(st, pvq_bits);

    let bits = shl(sub(pvq_bits, RC_BITS_RESERVED), 3);

    let mut bands_to_code: i16 = 0;
    for &value in &r[..bands] {
        if value > 0 {
            bands_to_code = add(bands_to_code, 1);
        }
    }

    let strict_bits = if core == 0 {
        // ACELP_CORE
        srt_vec_ind16(r, &mut r_sort, &mut i_sort, bands as i16);
        1
    } else {
        for (i, slot) in i_sort.iter_mut().enumerate().take(bands) {
            *slot = i as i16;
        }
        0
    };

    let mut coded_bands: i16 = 0;
    for &is in i_sort.iter().take(bands) {
        let is = is as usize;
        if r[is] > 0 {
            let adjustment = band_bits_adjustment(
                st.rc_num_bits,
                st.rc_range,
                bits,
                bands_to_code,
                bands_to_code - coded_bands,
                sfmsize[is],
                r[is],
                bit_pool,
            );
            let band_bits = adjustment.bband_adj;
            let mut bits_left = adjustment.brem;
            bit_pool = adjustment.breservplus;

            let start = sfm_start[is].max(0) as usize;
            pvq_decode_band(
                st,
                &mut pulse_vector[start..],
                &mut npulses[is],
                &mut coefs_quant[start..],
                sfmsize[is],
                band_bits,
                &mut bits_left,
                strict_bits,
            );

            coded_bands = add(coded_bands, 1);
        } else {
            for j in sfm_start[is].max(0) as usize..sfm_end[is].max(0) as usize {
                coefs_quant[j] = 0;
                pulse_vector[j] = 0;
            }
        }
    }

    rc_dec_finish(st);
}

/// `pvq_core_dec_fx`: decode the PVQ-coded spectrum of `nb_sfm` bands into `coefs_quant` (Q12, set
/// in `q_coefs`) from `bits_tot` bits with the bit allocation `r` (Q3, zeroed for bands that got
/// no pulses, as `rs` is when given); `npulses` / `maxpulse` receive each band's pulse count and
/// largest pulse. Returns `bits_tot`.
pub fn pvq_core_dec(
    st: &mut DecoderState,
    sfm_start: &[i16],
    sfm_end: &[i16],
    sfmsize: &[i16],
    coefs_quant: &mut [i16],
    q_coefs: &mut i16,
    bits_tot: i16,
    nb_sfm: i16,
    r: &mut [i16],
    rs: Option<&mut [i16]>,
    npulses: &mut [i16],
    maxpulse: &mut [i16],
    core: i16,
) -> i16 {
    let mut ord = [0i16; NB_SFM_MAX as usize];
    let mut pulse_vector = [0i16; L_FRAME48K];
    let mut gain_bits_array = [0i16; NB_SFM as usize];
    let mut fg_pred = [0i16; NB_SFM_MAX as usize];
    let bands = (nb_sfm.max(0) as usize).min(NB_SFM as usize);

    st.ber_occured_in_pvq = 0;

    let mut r_upd = shl(bits_tot, 3);
    assign_gain_bits(core, nb_sfm, sfmsize, r, &mut gain_bits_array, &mut r_upd);

    let pvq_bits = shr(r_upd, 3);

    pvq_decode_frame(
        st,
        coefs_quant,
        npulses,
        &mut pulse_vector,
        sfm_start,
        sfm_end,
        sfmsize,
        nb_sfm,
        r,
        pvq_bits,
        core,
    );

    if let Some(rs) = rs {
        for i in 0..bands {
            if npulses[i] <= 0 {
                rs[i] = 0;
            }
        }
    }

    for i in 0..bands {
        ord[i] = i as i16;
        if npulses[i] <= 0 {
            r[i] = 0;
        }
    }

    get_max_pulses(
        sfm_start,
        sfm_end,
        &ord,
        npulses,
        nb_sfm,
        &pulse_vector,
        maxpulse,
    );

    fine_gain_pred(
        sfm_start,
        sfm_end,
        sfmsize,
        &ord,
        npulses,
        maxpulse,
        Some(r),
        nb_sfm,
        coefs_quant,
        &mut pulse_vector,
        &mut fg_pred,
        core,
    );

    fine_gain_dec(st, &ord, nb_sfm, &gain_bits_array, &mut fg_pred);

    if st.ber_occured_in_pvq != 0 {
        set16(&mut fg_pred, 1, nb_sfm); // low complex ECU action in case of detected BER in PVQ decoding
    }
    apply_gain(&ord, sfm_start, sfm_end, nb_sfm, &fg_pred, coefs_quant);
    *q_coefs = 12;

    bits_tot
}

/// `decode_energies_fx`: decode the split energies of a band split into `np` parts of dimensions
/// `dim_part` with `qband` quanta (Q3), recursively halving the split: scales the parts' (negated)
/// gains `g_part` and gives each part its quanta `bits_part`.
pub fn decode_energies(
    st: &mut DecoderState,
    np: i16,
    dim_part: &[i16],
    bits_part: &mut [i16],
    g_part: &mut [i16],
    qband: i16,
    bits_left: &mut i16,
    dim: i16,
    strict_bits: i16,
) {
    let mut index_phi: i16 = -1;

    let l_np = shr(np, 1);
    let r_np = sub(np, l_np);
    let (ln, n) = (l_np.max(0) as usize, np.max(0) as usize);

    let mut l_dim: i16 = 0;
    for &part in &dim_part[..ln] {
        l_dim = add(l_dim, part);
    }
    let r_dim = sub(dim, l_dim);

    let density = obtain_energy_quantizer_density(dim, qband);
    let qzero = range_coder_finalization_f_bits(st.rc_num_bits, st.rc_range);

    density_symbol_index_decode(st, density, r_dim, l_dim, &mut index_phi);
    let proj = density_angle2_rms_proj_dec(density, index_phi);
    // The reference's out-parameters are (oppQ15, nearQ15) = (&ir, &il).
    let ir = proj.opp_q15;
    let il = proj.near_q15;
    let opp_r_q3 = proj.opp_ratio_q3;

    let l_gain = il; // Q15
    let r_gain = ir; // Q15

    for gain in &mut g_part[..ln] {
        *gain = mult_r(l_gain, *gain);
    }

    for gain in &mut g_part[ln..n] {
        *gain = mult_r(r_gain, *gain);
    }

    let split = near_opp_split_adjustment(
        qband,
        qzero,
        st.rc_num_bits,
        st.rc_range,
        *bits_left,
        strict_bits,
        np,
        dim_part[0],
        dim_part[n - 1],
        l_dim,
        r_dim,
        opp_r_q3,
    );
    let l_bits = split.qnear;
    let r_bits = split.qopp;
    *bits_left = split.qglobalupd;

    if sub(l_np, 1) > 0 {
        decode_energies(
            st,
            l_np,
            dim_part,
            bits_part,
            g_part,
            l_bits,
            bits_left,
            l_dim,
            strict_bits,
        );
    } else {
        bits_part[0] = l_bits;
    }

    if sub(r_np, 1) > 0 {
        decode_energies(
            st,
            r_np,
            &dim_part[ln..],
            &mut bits_part[ln..],
            &mut g_part[ln..],
            r_bits,
            bits_left,
            r_dim,
            strict_bits,
        );
    } else {
        bits_part[1] = r_bits;
    }
}

/// `densitySymbolIndexDecode_fx`: range-decode the split-angle index `index_phi` of an energy
/// quantiser of `density` levels for a split into `near_sz` / `opp_sz` coefficients (-1 when the
/// density leaves nothing to code). The probability model is triangular, skewed by the split.
pub fn density_symbol_index_decode(
    st: &mut DecoderState,
    density: i16,
    opp_sz: i16,
    near_sz: i16,
    index_phi: &mut i16,
) {
    let alpha: i16;

    if (0xFFFE_u16 as i16 & density) == 0 {
        // odd density exit
        *index_phi = -1;
        return;
    }

    let sym_freq: i32;
    let cum_freq: i32;

    let mut angle = atan2(sqrt_dim(opp_sz), sqrt_dim(near_sz));
    angle = shl(angle, 1);
    angle = mult_r(angle, 20861);
    let c = mult_r(density, angle);
    let density_c = sub(density, c);

    let mut tot = l_mac0(1, density, add(density, 1));
    if c == 0 {
        let dec_freq = rc_decode(st, tot as u32) as i32;

        let density1 = add(density, 1);
        let mut acc = l_mult0(density1, density1);
        acc = l_sub(acc, dec_freq);
        alpha = add(get_sqrt_word32(acc), density1);
        sym_freq = l_mac(1, sub(density, alpha), 1);
        cum_freq = l_mac0(l_mult(alpha, density), alpha, 1);
    } else if sub(c, density) == 0 {
        let dec_freq = rc_decode(st, tot as u32) as i32;

        alpha = get_sqrt_word32(dec_freq);
        sym_freq = l_add(l_shl(i32::from(alpha), 1), 1);
        cum_freq = l_mult0(alpha, alpha);
    } else {
        let mut acc = l_mult0(density, c);
        acc = mpy_fold(acc, density_c);
        acc = l_shr(acc, 1);
        tot = l_add(l_add(acc, i32::from(density)), 1);

        let dec_freq = rc_decode(st, tot as u32) as i32;

        acc = l_mult0(sub(density_c, 1), density_c);
        acc = mpy_fold(acc, c);
        acc = l_shr(acc, 1);
        acc = l_add(acc, l_add(i32::from(density), 1));
        acc = l_sub(acc, l_add(i32::from(c), 1));
        acc = l_sub(tot, acc);
        if l_sub(dec_freq, acc) < 0 {
            acc = l_add(i32::from(density_c), l_shl(dec_freq, 2));
            acc = l_sub(acc, 2);
            acc = mpy_fold(acc, density_c);
            acc = l_shr(acc, 1);
            acc = l_add(acc, 1);
            let tmp2 = get_sqrt_word32(acc);
            acc = l_add(i32::from(density_c), i32::from(tmp2));
            acc = l_sub(acc, 1);
            let mut expo: i16 = 0;
            let r = ratio(acc, l_shl(i32::from(density_c), 1), &mut expo);
            alpha = shr(r, add(14, expo));

            acc = l_mult(alpha, density_c);
            sym_freq = l_add(acc, 1);
            acc = l_mult0(sub(alpha, 1), density_c);
            acc = l_add(acc, 1);
            cum_freq = l_mult0(alpha, extract_l(acc));
        } else {
            let density1 = add(density, 1);
            let density2 = add(shl(density, 1), 1);

            acc = l_mult0(density, density1);
            acc = mpy_fold(acc, c);
            acc = l_shr(acc, 1);
            acc = l_add(i32::from(density1), acc);
            acc = l_add(dec_freq, acc);
            acc = l_sub(tot, acc);
            acc = mpy_fold(acc, c);
            acc = l_shr(acc, 1 - 2);

            let mut tmp2 = extract_l(l_mac0(1, c, density2));
            let mut tmp1 = l_mult0(tmp2, tmp2);
            tmp1 = l_add(tmp1, acc);
            tmp2 = get_sqrt_word32(tmp1);
            if l_msu0(tmp1, tmp2, tmp2) != 0 {
                tmp2 = add(tmp2, 1);
            }

            acc = l_mult0(c, density2);
            acc = l_add(acc, 1);
            acc = l_sub(acc, i32::from(tmp2));
            let mut expo: i16 = 0;
            let r = ratio(acc, l_shl(i32::from(c), 1), &mut expo);
            alpha = shr(r, add(14, expo));

            let density_alpha = sub(density, alpha);
            sym_freq = l_mac(1, density_alpha, c);
            acc = l_mult0(density_alpha, add(density_alpha, 1));
            acc = mpy_fold(acc, c);
            acc = l_shr(acc, 1);
            acc = l_sub(acc, i32::from(alpha));
            acc = l_add(acc, i32::from(density1));
            cum_freq = l_sub(tot, acc);
        }
    }

    rc_dec_update(st, cum_freq as u32, sym_freq as u32);
    *index_phi = alpha;
}

/// `get_pvq_splits_fx`: the number of parts (1..=`MAX_SPLITS`, at most `sfmsize`) a band of
/// `sfmsize` coefficients with `band_bits` (Q3) is split into, reading the extra-split flag when
/// one is coded; `bits` receives the quanta the flag cost (Q3).
fn get_pvq_splits(st: &mut DecoderState, band_bits: i16, sfmsize: i16, bits: &mut i16) -> i16 {
    let mut np: i16 = if band_bits == 0 {
        1
    } else {
        let acc = l_mult0(band_bits, 0x7a44);
        let mut np = extract_l(l_shr(acc, 23)); // Get integer part
        if (acc & 0x7f_ffff) != 0 {
            // If fractional part != 0, add 1
            np = add(np, 1); // ceil operation
        }
        np
    };
    *bits = 0;
    if sub(np, MAX_SPLITS) < 0 {
        let acc = l_mult0((8 * THR_ADD_SPLIT) as i16, sfmsize);
        if l_sub(i32::from(band_bits), acc) > 0 {
            let flag = rc_dec_bits(st, 1);
            *bits = 8;
            if flag != 0 {
                np = add(np, 1);
            }
        }
    }

    // The following code assumes that PVQ_MAX_BAND_SIZE is 64
    let mut i = shr(sfmsize, 6); // 6 = log2(64) = log2(PVQ_MAX_BAND_SIZE)
    if (sfmsize & 0x3f) != 0 {
        i = add(i, 1);
    }

    np = i.max(np);
    np = np.min(MAX_SPLITS);
    np = np.min(sfmsize); // The code line assumes that MIN_BAND_SIZE is 1
                          // A band of no coefficients is never coded; keep the split count a valid one.
    np.max(1)
}
