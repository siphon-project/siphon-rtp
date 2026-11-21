//! Low-rate HQ (LR-MDCT) decoding (TS 26.442 `lib_dec/hq_lr_dec_fx.c`; TS 26.445 §6.2.3.2):
//! band energies, peak-to-average flags, the envelope-adaptive bit allocation, the TCQ spectrum,
//! fine gains, noise filling and, at SWB 13.2 / 16.4 kbit/s, the LR SWB bandwidth extension.

use crate::evs::basop::{l_extract_lc, mpy_32_16_1, mult_32_16};
use crate::evs::cnst::{
    ABS_ENG_OFFSET, BANDS_MAX, BITS_ABS_ENG, BITS_DE_8SPOS, BITS_DE_CMODE, BITS_DE_FCOMP,
    BITS_DE_HMODE, BITS_DE_LSB, BITS_MAX_DEPTH, DE_OFFSET0, DE_OFFSET1, HQ_13K20, HQ_16K40,
    HQ_HARMONIC, HQ_NORMAL, HQ_TRANSIENT, LOW_RATE_HQ_CORE, LOW_RATE_HQ_CORE_TRAN,
    LRMDCT_BE_OFFSET, L_FRAME16K, L_FRAME32K, L_FRAME48K, L_FRAME8K, SPT_SHORTEN_SBNUM, SWB,
};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::hq2_bit_alloc::{hq2_bit_alloc, hq2_bit_alloc_har};
use crate::evs::com::hq2_core_com::{
    hq2_core_configure, mdct_spectrum_denorm, reverse_transient_frame_energies,
    spt_shorten_domain_band_restore, spt_shorten_domain_band_save, spt_shorten_domain_pre,
    spt_swb_peakpos_tmp_save,
};
use crate::evs::com::hq2_noise_inject::hq2_noise_inject;
use crate::evs::com::math_op::{isqrt_lc, pow2};
use crate::evs::com::swb_bwe_com_lr::{
    get_usebit_npswb, post_hq2_swb, preset_hq2_swb, return_bits_normal2, updat_prev_frm,
};
use crate::evs::com::tools::{copy32, set16, set32};
use crate::evs::dec::hq_env_dec::decode_envelope_indices;
use crate::evs::dec::state::DecoderState;
use crate::evs::dec::swb_bwe_dec_lr::swb_bwe_dec_lr;
use crate::evs::dec::tcq_core_dec::tcq_core_lr_dec;
use crate::evs::rom::{BITS_LAGINDICES_MODENORMAL_FX, HESTABLE_FX};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_abs, l_add, l_deposit_h, l_mult, l_negate, l_shl, l_shr,
    l_sub, mult, negate, norm_l, norm_s, round_word, shl, shr, sub,
};
use crate::itu::stl2009::div_l;

const BANDS: usize = BANDS_MAX as usize;
const FRAME_MAX: usize = L_FRAME48K as usize;
const SPT: usize = SPT_SHORTEN_SBNUM as usize;

/// `Calc_inv`: `2^29 / L_tmp`-style reciprocal of the high word of `l_tmp`, as a Q15 mantissa with
/// its exponent in `exp`; a zero high word gives `0x7fff` with exponent 0.
pub fn calc_inv(l_tmp: i32, exp: &mut i16) -> i16 {
    let mut tmp = extract_h(l_tmp);
    if tmp != 0 {
        let exp2 = norm_s(tmp);
        tmp = shl(tmp, exp2);
        tmp = div_s(16384, tmp);
        *exp = sub(29, exp2);
    } else {
        tmp = 0x7fff;
        *exp = 0;
    }
    tmp
}

/// `spt_shorten_domain_set_dec_fx`: update the shortened band information based on the p2a
/// analysis. Each of the last `SPT_SHORTEN_SBNUM` bands that is flagged peaky carries one bit
/// choosing the shortened layout `new_band_*` over the configured one.
// Index loops mirror the reference's pointer walks so the two can be diffed.
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
pub fn spt_shorten_domain_set_dec(
    st: &mut DecoderState,
    p2a_flags: &[i16],
    new_band_start: &[i16],
    new_band_end: &[i16],
    new_band_width: &[i16],
    bands: i16,
    band_start: &mut [i16],
    band_end: &mut [i16],
    band_width: &mut [i16],
    bit_budget: &mut i16,
) {
    let mut spt_shorten_flag = [0i16; SPT_SHORTEN_SBNUM as usize];
    let mut j: usize = 0;
    for k in sub(bands, SPT_SHORTEN_SBNUM)..bands {
        let k = k as usize;
        spt_shorten_flag[j] = 0;
        if sub(p2a_flags[k], 1) == 0 {
            spt_shorten_flag[j] = get_next_indice(st, 1) as i16;
            *bit_budget = sub(*bit_budget, 1);
            if sub(spt_shorten_flag[j], 1) == 0 {
                band_start[k] = new_band_start[j];
                band_end[k] = new_band_end[j];
                band_width[k] = new_band_width[j];
            }
        }
        j += 1;
    }
}

/// `small_symbol_dec_tran_fx`: Huffman decoding of the differential energies of a transient
/// frame. Returns the bits read (counting the coding-mode bit).
pub fn small_symbol_dec_tran(
    st: &mut DecoderState,
    qbidx: &mut [i16; BANDS],
    bands: i16,
    is_transient: i16,
) -> i16 {
    let mut difidx = [0i16; BANDS];

    // Decoding differential energies
    let mut bits = decode_envelope_indices(
        st,
        0,
        bands,
        0,
        &mut difidx,
        LOW_RATE_HQ_CORE_TRAN,
        is_transient,
    );
    bits = add(bits, BITS_DE_FCOMP);

    // counting 1 bit for band_energy_huff_coding_mode
    bits = add(bits, BITS_DE_HMODE);

    // converting to original values
    for i in 0..bands as usize {
        qbidx[i] = sub(difidx[i], LRMDCT_BE_OFFSET);
    }
    bits
}

/// `small_symbol_dec_fx`: Huffman decoding of the differential energies, MSBs then one packed LSB
/// per band. Returns the bits read (counting the coding-mode bit).
pub fn small_symbol_dec(
    st: &mut DecoderState,
    qbidx: &mut [i16; BANDS],
    bands: i16,
    is_transient: i16,
) -> i16 {
    let mut difidx = [0i16; BANDS];

    // Decoding MSB bits
    let mut bits =
        decode_envelope_indices(st, 0, bands, 0, &mut difidx, LOW_RATE_HQ_CORE, is_transient);
    bits = add(bits, BITS_DE_FCOMP);

    // counting 1 bit for band_energy_huff_coding_mode
    bits = add(bits, BITS_DE_HMODE);

    // Decoding LSB bit packing
    for slot in difidx.iter_mut().take(bands as usize) {
        let lsb = get_next_indice(st, BITS_DE_LSB) as i16;
        *slot = shl(*slot, 1) | lsb;
    }

    // counting bits for LSB
    bits = add(bits, bands);

    // converting to original values
    for i in 1..bands as usize {
        qbidx[i] = sub(difidx[i], DE_OFFSET1);
    }
    qbidx[0] = sub(difidx[0], DE_OFFSET0);
    bits
}

/// `decode_huff_8s_fx`: walk the packed Huffman tree `hufftab` (each node: low nibble = bits to
/// read, the rest = jump to the child pair; a leaf is the negated symbol), adding the bits read to
/// `rbits`. Returns the symbol.
pub fn decode_huff_8s(st: &mut DecoderState, hufftab: &[i16], rbits: &mut i16) -> i16 {
    let mut pos: usize = 0;
    // every jump of the reference's tree lands inside it whatever the bits; the zero fallback for a
    // position outside the table is unreachable and only keeps an inconsistent table from panicking
    let node = |pos: usize| hufftab.get(pos).copied().unwrap_or(0);
    while node(pos) > 0 {
        let value = node(pos);
        *rbits = add(*rbits, value & 0xf);
        let bit = get_next_indice(st, value & 0xf) as i16;
        pos += add(shr(value, 4), bit) as usize;
    }
    negate(node(pos))
}

/// `large_symbol_dec_fx`: decoding of the differential energies when they are too large for the
/// small-symbol code: an 8-symbol Huffman code with at most one or two absolute outliers, or an
/// MSB/LSB split with a common shift. Returns the bits read.
// Index loops mirror the reference's pointer walks so the two can be diffed.
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
pub fn large_symbol_dec(st: &mut DecoderState, qbidx: &mut [i16; BANDS], bands: i16) -> i16 {
    let mut cntbits: i16 = 1;
    let ns2mode = get_next_indice(st, 1) as i16;
    if ns2mode == 0 {
        let ns2mode0 = get_next_indice(st, 1) as i16;
        let ns2mode1 = get_next_indice(st, 1) as i16;
        cntbits = add(cntbits, 1 + 1);

        if ns2mode0 == 0 {
            let pos_outlyer: i16;
            if sub(ns2mode1, 1) == 0 {
                // 5 bits: always inside the BANDS_MAX (32) entries of qbidx
                pos_outlyer = get_next_indice(st, BITS_DE_8SPOS) as i16;
                cntbits = add(cntbits, BITS_DE_8SPOS);
                qbidx[pos_outlyer as usize] =
                    sub(get_next_indice(st, BITS_ABS_ENG) as i16, ABS_ENG_OFFSET);
                cntbits = add(cntbits, BITS_ABS_ENG);
            } else {
                pos_outlyer = -1;
            }
            for i in 0..pos_outlyer {
                cntbits = large_symbol_dec_huff(st, qbidx, i, cntbits);
            }
            for i in add(pos_outlyer, 1)..bands {
                cntbits = large_symbol_dec_huff(st, qbidx, i, cntbits);
            }
        } else {
            let pos_outlyer: i16;
            if sub(ns2mode1, 1) == 0 {
                pos_outlyer = get_next_indice(st, BITS_DE_8SPOS) as i16;
                cntbits = add(cntbits, BITS_DE_8SPOS);
                qbidx[0] = sub(get_next_indice(st, BITS_ABS_ENG) as i16, ABS_ENG_OFFSET);
                cntbits = add(cntbits, BITS_ABS_ENG);
                qbidx[pos_outlyer as usize] =
                    sub(get_next_indice(st, BITS_ABS_ENG) as i16, ABS_ENG_OFFSET);
                cntbits = add(cntbits, BITS_ABS_ENG);
            } else {
                pos_outlyer = 0;
                qbidx[0] = sub(get_next_indice(st, BITS_ABS_ENG) as i16, ABS_ENG_OFFSET);
                cntbits = add(cntbits, BITS_ABS_ENG);
            }
            for i in 1..pos_outlyer {
                cntbits = large_symbol_dec_huff(st, qbidx, i, cntbits);
            }
            for i in pos_outlyer + 1..bands {
                cntbits = large_symbol_dec_huff(st, qbidx, i, cntbits);
            }
        }
    } else {
        let basic_shift = get_next_indice(st, BITS_MAX_DEPTH) as i16;
        cntbits = add(cntbits, BITS_MAX_DEPTH);

        for i in 0..bands as usize {
            let mut bits: i16 = 0;
            qbidx[i] = sub(decode_huff_8s(st, &HESTABLE_FX, &mut bits), 4);
            qbidx[i] = shl(qbidx[i], basic_shift);
            cntbits = add(cntbits, bits);
        }
        for slot in qbidx.iter_mut().take(bands as usize) {
            let lsb = get_next_indice(st, basic_shift) as i16;
            *slot = add(*slot, lsb);
            cntbits = add(cntbits, basic_shift);
        }
    }
    cntbits
}

/// One Huffman-coded band of [`large_symbol_dec`]: `qbidx[i]` from the 8-symbol code, returning
/// the updated bit count.
fn large_symbol_dec_huff(
    st: &mut DecoderState,
    qbidx: &mut [i16; BANDS],
    i: i16,
    cntbits: i16,
) -> i16 {
    let mut bits: i16 = 0;
    // i < BANDS_MAX: the outlier position is 5 bits and bands <= BANDS_MAX
    qbidx[i as usize] = sub(decode_huff_8s(st, &HESTABLE_FX, &mut bits), 4);
    add(cntbits, bits)
}

/// `band_energy_dequant_fx`: decode the quantised band energies (Q14 log2 domain) into
/// `l_band_energy[0..bands]`. Returns the bits read.
pub fn band_energy_dequant(
    st: &mut DecoderState,
    l_band_energy: &mut [i32],
    bands: i16,
    l_qint: i32,
    eref: i16,
    is_transient: i16,
) -> i16 {
    let mut bq1 = [0i16; BANDS];
    let mut bq2 = [0i16; BANDS];

    // parsing energy part
    let deng_cmode = get_next_indice(st, BITS_DE_CMODE) as i16;
    let mut deng_bits: i16;
    if deng_cmode == 0 {
        deng_bits = large_symbol_dec(st, &mut bq2, bands);
        // counting 1 bit for deng coding mode
        deng_bits = add(deng_bits, BITS_DE_CMODE);
    } else {
        if is_transient != 0 {
            deng_bits = small_symbol_dec_tran(st, &mut bq2, bands, is_transient);
        } else {
            deng_bits = small_symbol_dec(st, &mut bq2, bands, is_transient);
        }
        // counting 1 bit for deng coding mode
        deng_bits = add(deng_bits, BITS_DE_CMODE);
    }

    // Get the reference energy
    let exp_normd = norm_l(l_qint);
    let rev_qint = div_s(0x4000, round_word(l_shl(l_qint, exp_normd))); // Q14-(29-16)+15-exp_normd
    let q_rev_qint = sub(14 - (29 - 16) + 15, exp_normd);
    let bq0 = round_word(l_shl(l_mult(eref, rev_qint), sub(5, q_rev_qint)));

    // Reconstruct quantized spectrum
    bq1[0] = add(bq2[0], bq0);
    for k in 1..bands as usize {
        bq1[k] = add(bq2[k], bq1[k - 1]);
    }
    for k in 0..bands as usize {
        l_band_energy[k] = mpy_32_16_1(l_qint, bq1[k]); // 29+0-15 -> Q14
    }

    if is_transient != 0 {
        reverse_transient_frame_energies(l_band_energy, bands);
    }
    deng_bits
}

/// `p2a_threshold_dequant_fx`: the peak-to-average flags; every band below the last `p2a_bands`
/// is flagged, the last `p2a_bands` carry one bit each. Returns the bits read.
pub fn p2a_threshold_dequant(
    st: &mut DecoderState,
    p2a_flags: &mut [i16],
    bands: i16,
    p2a_bands: i16,
) -> i16 {
    let first = sub(bands, p2a_bands);
    for flag in p2a_flags.iter_mut().take(first.max(0) as usize) {
        *flag = 1;
    }
    let mut j: i16 = 0;
    for k in first..bands {
        p2a_flags[k as usize] = get_next_indice(st, 1) as i16;
        j = add(j, 1);
    }
    j
}

/// `mdct_spectrum_fine_gain_dec_fx`: apply the fine gains of the `ngq` most-allocated bands
/// (`k_sort[bands - ngq..bands]`) to the denormalised spectrum `l_y2`.
pub fn mdct_spectrum_fine_gain_dec(
    st: &mut DecoderState,
    l_y2: &mut [i32],
    band_start: &[i16],
    band_end: &[i16],
    k_sort: &[i16],
    bands: i16,
    l_qint: i32,
    ngq: i16,
    gqlevs: i16,
    gqbits: i16,
) {
    // The reference leaves gain_table_fx[gqlevs..] uninitialised; an index there needs a
    // gqbits-bit code above gqlevs - 1, which the configured gqlevs (a power of two) never admits.
    // Zeroed here, so a corrupt configuration reads a defined value.
    let mut gain_table = [0i16; 32];

    // Fine gain quantization on only the most significant energy bands
    let mut exp_normn = norm_l(l_qint);
    exp_normn = sub(exp_normn, 1);
    let exp_normd = norm_s(gqlevs);
    let delta = div_l(l_shl(l_qint, exp_normn), shl(gqlevs, exp_normd));
    let q_delta = add(sub(exp_normn, exp_normd), 28);
    let l_delta = l_shl(l_deposit_h(delta), sub(13, q_delta)); // Q(28-15+1+16=29)
    let mut l_q = l_shr(l_sub(l_delta, l_qint), 1);

    for slot in gain_table.iter_mut().take(gqlevs.clamp(0, 32) as usize) {
        // Mult_32_16(L_q, 0x4000) -> L_shr(L_q, 1)
        let l_temp = l_shr(l_shr(l_q, 1), sub(29, 16));
        let (temp_hi, temp_lo) = l_extract_lc(l_temp);
        let q_gt = sub(14, temp_hi);
        *slot = extract_l(pow2(14, temp_lo)); // Qgt
        l_q = l_add(l_q, l_delta);
        *slot = shl(*slot, sub(14, q_gt)); // Qgt -> Q14
    }

    for k in sub(bands, ngq)..bands {
        let imin = get_next_indice(st, gqbits) as usize;
        let gamma = gain_table.get(imin).copied().unwrap_or(0);
        let band = k_sort[k as usize] as usize;
        for i in band_start[band]..=band_end[band] {
            let i = i as usize;
            if l_y2[i] >= 0 {
                l_y2[i] = l_shl(mpy_32_16_1(l_y2[i], gamma), 1);
            } else {
                l_y2[i] = l_negate(l_shl(mpy_32_16_1(l_abs(l_y2[i]), gamma), 1));
            }
        }
    }
}

/// What the energy analysis of [`hq_lr_dec`] hands its bit-allocation stage: the linear band
/// energies (`Ep_fx`, Q-6) and their per-line RMS (`Ep_tmp_fx`, Q13; the WB adjustment rescales
/// it to Q15 in place).
struct BandShape {
    ep: [i32; BANDS],
    ep_tmp: [i32; BANDS],
}

/// The linear band energies and per-line RMS of [`hq_lr_dec`] from the quantised log2 band
/// energies `l_band_energy` (Q14).
// Index loops mirror the reference's walks so the two can be diffed.
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
fn hq_lr_dec_band_shape(l_band_energy: &[i32], band_width: &[i16], bands: usize) -> BandShape {
    let mut shape = BandShape {
        ep: [0; BANDS],
        ep_tmp: [0; BANDS],
    };
    let q_band_energy: i16 = 14;
    for i in 0..bands {
        let l_tmp = l_shl(l_band_energy[i], sub(16, q_band_energy)); // Q16
        let (exp, frac1) = l_extract_lc(l_tmp); // Extract exponent of L_tmp
        let l_tmp = pow2(30, frac1);
        let exp = sub(exp, 30);
        shape.ep[i] = l_shl(l_tmp, sub(exp, 6).max(-31)); // Q -6
    }

    for i in 0..bands {
        let l_tmp2 = shape.ep[i];
        let l_tmp = l_tmp2.max(1);
        let exp = norm_l(l_tmp);
        let tmp = extract_h(l_shl(l_tmp, exp));

        let l_tmp3 = i32::from(band_width[i]);
        let mut exp2 = norm_l(l_tmp3);
        let mut tmp2 = extract_h(l_shl(l_tmp3, exp2));

        exp2 = sub(exp, exp2); // Denormalize and substract

        let tmp3 = sub(tmp2, tmp);
        if tmp3 > 0 {
            tmp2 = shr(tmp2, 1);
        }
        if tmp3 > 0 {
            exp2 = add(exp2, 1);
        }
        let tmp = div_s(tmp2, tmp);
        let l_tmp = l_deposit_h(tmp);
        let l_tmp = isqrt_lc(l_tmp, &mut exp2); // Q(31-exp2)
        shape.ep_tmp[i] = l_shr(l_tmp, sub(15, exp2)); // Q13
    }
    shape
}

/// The parameters of [`hq_lr_dec`]'s bit allocation that the envelope adjustments below pass
/// through to `hq2_bit_alloc_fx`.
struct AllocParams<'a> {
    bands: i16,
    band_start: &'a [i16],
    band_end: &'a [i16],
    band_width: &'a [i16],
    bit_alloc_weight: i16,
    num_bits: i16,
    hqswb_clas: i16,
    is_transient: i16,
    p2a_bands: i16,
}

/// The NB (`inner_frame == L_FRAME8k`, at most 13.2 kbit/s, not transient) branch of
/// [`hq_lr_dec`]: read the two bits saying whether the previous frame's last two bands got bits,
/// reshape the band energies the allocation sees, and allocate. Returns `adjustFlag`.
// Index loops mirror the reference's walks so the two can be diffed.
#[allow(clippy::needless_range_loop, clippy::explicit_counter_loop)]
fn hq_lr_dec_alloc_nb(
    st: &mut DecoderState,
    p: &AllocParams<'_>,
    shape: &BandShape,
    l_band_energy: &[i32],
    p2a_flags: &mut [i16; BANDS],
    l_rk: &mut [i32; BANDS],
    bit_budget: &mut i16,
    last_bitalloc_max_band: &mut [i16; 2],
) -> i16 {
    let bands = p.bands;
    let nb = bands as usize;
    let ep_tmp = &shape.ep_tmp;
    let mut l_band_energy_tmp = [0i32; BANDS];
    let mut p2a_flags_tmp = [0i16; BANDS];
    let mut adjust_flag: i16 = 0;

    // decode the last p2a_bands-1 subbands bit-allocation index of the previous frame
    for slot in last_bitalloc_max_band.iter_mut() {
        *slot = get_next_indice(st, 1) as i16;
    }
    let mut lowband: i16 = 6;
    let trans_bit: i16 = 2;
    *bit_budget = sub(*bit_budget, trans_bit);
    let mut gama: i16 = 27852; // Q15 0.85f
    let mut beta: i16 = 17203; // Q14 1.05f
    let high = sub(bands, trans_bit) as usize;
    p2a_flags_tmp[high..high + 2].fill(0);

    if l_sub(st.core_brate, i32::from(HQ_13K20)) == 0 {
        beta = 13107; // 14 1.25f
        gama = 31130; // 0.95f
        p2a_flags_tmp[high..nb].copy_from_slice(&p2a_flags[high..nb]);
    }

    // calculate the the low band/high band energy and the variance/avrage of the envelopes
    let mut ep_vari: i32 = 0;
    let mut ep_avrg: i32 = 0;
    let mut ep_avrg_l: i32 = 0;
    let mut ep_peak: i32 = 0;
    for i in 0..nb {
        if sub(i as i16, lowband) >= 0 {
            ep_vari = l_add(ep_vari, l_abs(l_sub(ep_tmp[i], ep_tmp[i - 1]))); // Q15
            ep_avrg = l_add(ep_avrg, ep_tmp[i]); // Q15
        } else {
            ep_avrg_l = l_add(ep_avrg_l, ep_tmp[i]); // Q15
            if l_sub(ep_tmp[i], ep_peak) > 0 {
                ep_peak = l_add(ep_tmp[i], 0); // Q15
            }
        }
    }

    // modify the last p2a_bands subbands band_energies
    l_band_energy_tmp[..nb].copy_from_slice(&l_band_energy[..nb]); // Q_band_energy
    let l_tmp = mult_32_16(ep_peak, 24576); // Q(13+14-15 = 12) 1.5 lowband = 6;
    let l_tmp2 = mult_32_16(ep_peak, shl(sub(bands, lowband), 9)); // Q(13+9-15 = 7)
    let l_tmp3 = mult_32_16(ep_avrg, 1126); // Q(13+9-15 = 7)
    if ((l_sub(l_tmp, l_shr(ep_avrg_l, 1)) < 0 && l_sub(st.core_brate, i32::from(HQ_13K20)) == 0)
        || l_sub(st.core_brate, i32::from(HQ_13K20)) < 0)
        && l_sub(l_tmp2, l_tmp3) < 0
        && l_sub(l_tmp2, l_shr(ep_avrg, 7)) > 0
    {
        for i in lowband as usize..nb {
            let l_tmp = mult_32_16(ep_avrg, 24576); // Q(13+14-15 = 12) 1.5
            if l_sub(l_shr(ep_tmp[i], 1), l_tmp) < 0 {
                let l_tmp = mult_32_16(ep_peak, sub(bands, lowband)); // Q(13+0-15 = -2)
                let mut exp: i16 = 0;
                let tmp = calc_inv(l_shl(l_tmp, 14), &mut exp);
                let l_tmp = l_shl(mult_32_16(ep_avrg, tmp), sub(13, exp)); // Q15
                let l_tmp2 = l_add(l_tmp, 13107); // 15
                let tmp2 = extract_l(l_tmp2.max(16384).min(i32::from(gama))); // 15
                l_band_energy_tmp[i] = mult_32_16(l_band_energy_tmp[i], tmp2); // Q_band_energy
            }
        }
    } else {
        let mut j: usize = 0;
        for i in high..nb {
            let mut alpha: i16 = 16384; // Q14
            if sub(p2a_flags_tmp[i], 1) == 0 {
                let l_tmp = mult_32_16(ep_tmp[i], sub(bands, lowband)); // Q(13+0-15 = -2)
                let mut exp: i16 = 0;
                let tmp = calc_inv(l_shl(l_tmp, 14), &mut exp);
                let l_tmp = mult_32_16(ep_vari, 3277); // 13+15-15=13
                let l_tmp = l_shl(mult_32_16(l_tmp, tmp), sub(12, exp)); // Q14
                                                                         // the reference writes Calc_inv out inline here ("when the divisor is zero,
                                                                         // happens rarely")
                let tmp2 = calc_inv(ep_avrg, &mut exp); // Q(15+14-exp=29-exp)
                let l_tmp2 = mult_32_16(ep_vari, 6554); // 13+15-15=13
                let l_tmp2 = l_shl(mult_32_16(l_tmp2, tmp2), sub(13, exp)); // Q14
                let l_tmp = l_tmp.min(l_tmp2); // 14
                let tmp = extract_l(l_tmp.min(13107)); // 14
                alpha = add(16384, tmp);
            }
            let flag = last_bitalloc_max_band[j];
            j += 1;
            if sub(flag, 1) == 0 {
                let l_tmp = mult_32_16(ep_tmp[i], sub(bands, lowband)); // Q(13+0-15 = -2)
                let mut exp: i16 = 0;
                let tmp = calc_inv(l_shl(l_tmp, 14), &mut exp);
                let l_tmp = l_shl(mult_32_16(ep_avrg, tmp), sub(14, exp)); // Q14
                let l_tmp = l_tmp.max(16384); // 14
                let tmp = extract_l(l_tmp.min(i32::from(beta))); // 14
                alpha = shl(mult(alpha, tmp), 1); // 14+14-15 +1=14
            } else {
                let mut exp: i16 = 0;
                let tmp2 = calc_inv(ep_avrg, &mut exp); // Q(29-exp), inline in the reference
                let l_tmp = l_shl(mult_32_16(ep_tmp[i], tmp2), sub(19, exp)); // Q20
                let l_tmp = mult_32_16(l_tmp, shl(sub(bands, lowband), 9)); // 20 +9 -15 =14
                let l_tmp = l_tmp.max(13926); // 14
                let tmp2 = extract_l(l_tmp.min(16384)); // 14
                alpha = shl(mult(alpha, tmp2), 1); // 14+14-15+1 =14
            }
            // Q(Q_band_energy+14-15 +1= Q_band_energy)
            l_band_energy_tmp[i] = l_shl(mult_32_16(l_band_energy_tmp[i], alpha), 1);
        }
    }

    lowband = 3;
    let mut ep_avrg: i32 = 0;
    let mut ep_avrg_l: i32 = 0;
    let mut ep_peak: i32 = 0;
    for i in 0..nb {
        if sub(i as i16, lowband) >= 0 {
            ep_avrg = l_add(ep_avrg, ep_tmp[i]); // Q15
        } else {
            ep_avrg_l = l_add(ep_avrg_l, l_shr(ep_tmp[i], 1)); // Q12
            if l_sub(ep_tmp[i], ep_peak) > 0 {
                ep_peak = l_add(ep_tmp[i], 0); // Q13
            }
        }
    }
    let l_tmp = mult_32_16(ep_peak, 28262); // Q(13+14-15 = 12) 1.725 lowband = 3;
    let l_tmp2 = mult_32_16(ep_avrg_l, 24576); // Q(12+14-15 = 11)
    if l_sub(l_shr(ep_avrg, 2), l_tmp2) > 0
        && l_sub(l_shr(ep_avrg, 4), l_tmp2) < 0
        && l_sub(l_tmp, ep_avrg_l) > 0
    {
        adjust_flag = 1;
        for i in 0..lowband as usize {
            let mut exp: i16 = 0;
            let tmp = calc_inv(ep_avrg_l, &mut exp);
            let l_tmp = mult_32_16(ep_peak, tmp); // Q(exp+2)
            let l_tmp = mult_32_16(l_tmp, lowband); // Q(exp-13)
            let l_tmp = mult_32_16(l_tmp, 18842); // Q(exp-13)
            let l_tmp = l_shl(l_tmp, sub(27, exp)); // Q14 0.5
            let tmp2 = extract_l(l_tmp.min(19661)); // 14
            let l_tmp = mult_32_16(l_band_energy_tmp[i], tmp2); // Q(Q_band_energy-1)
            l_band_energy_tmp[i] = l_shl(l_tmp, 1); // Q_band_energy
        }
    }

    hq2_bit_alloc(
        &l_band_energy_tmp,
        bands,
        l_rk,
        bit_budget,
        p2a_flags,
        p.bit_alloc_weight,
        p.band_width,
        p.num_bits,
        p.hqswb_clas,
        st.bwidth,
        p.is_transient,
    );
    adjust_flag
}

/// The low-band / high-band split [`hq_lr_dec_alloc_wb`] hands the noise filling.
struct WbSplit {
    adjust_flag: i16,
    bw_low: i16,
    bw_high: i16,
    ener_l: i32,
    ener_h: i32,
}

/// The WB (`inner_frame == L_FRAME16k`, not transient) branch of [`hq_lr_dec`]: as
/// [`hq_lr_dec_alloc_nb`] over the last `p2a_bands` bands, also measuring the low/high band
/// energies the noise filling uses. Rescales `ep_tmp` to Q15 in place, as the reference does.
// Index loops mirror the reference's walks so the two can be diffed.
#[allow(clippy::needless_range_loop)]
fn hq_lr_dec_alloc_wb(
    st: &mut DecoderState,
    p: &AllocParams<'_>,
    shape: &mut BandShape,
    l_band_energy: &[i32],
    p2a_flags: &mut [i16; BANDS],
    l_rk: &mut [i32; BANDS],
    bit_budget: &mut i16,
    last_bitalloc_max_band: &mut [i16; 2],
) -> WbSplit {
    let bands = p.bands;
    let nb = bands as usize;
    let p2a_bands = p.p2a_bands;
    let mut l_band_energy_tmp = [0i32; BANDS];
    let mut adjust_flag: i16 = 0;

    // bits in high bands to indicate the last 2 subbands is allocated bits or not
    *bit_budget = sub(*bit_budget, 2);
    for slot in last_bitalloc_max_band.iter_mut() {
        *slot = get_next_indice(st, 1) as i16;
    }
    for value in shape.ep_tmp.iter_mut().take(nb) {
        *value = l_shl(*value, 2);
    }
    let ep = &shape.ep;
    let ep_tmp = &shape.ep_tmp;

    let mut lowband: i16 = 8;
    let highband: i16 = if l_sub(st.core_brate, i32::from(HQ_13K20)) == 0 {
        15
    } else {
        16
    };
    let bw_low = sub(
        p.band_start[highband as usize],
        p.band_start[lowband as usize],
    );
    let bw_high = sub(add(p.band_end[nb - 1], 1), p.band_start[highband as usize]);

    // calculate the the low band/high band energy and the variance/avrage of the envelopes
    let mut ener_l: i32 = 0;
    let mut ener_h: i32 = 0;
    let mut ep_vari: i32 = 0;
    let mut ep_avrg: i32 = 0;
    for i in 0..nb {
        let ii = i as i16;
        if sub(ii, lowband) >= 0 && add(sub(ii, bands), p2a_bands) < 0 {
            ep_vari = l_add(ep_vari, l_abs(l_sub(ep_tmp[i], ep_tmp[i - 1]))); // Q15
            ep_avrg = l_add(ep_avrg, ep_tmp[i]); // Q15
        }
        if sub(ii, highband) >= 0 {
            ener_h = l_add(ener_h, l_shl(ep[i], 2)); // Q0
        } else if sub(ii, lowband) >= 0 {
            ener_l = l_add(ener_l, l_shl(ep[i], 2)); // Q0
        }
    }

    // modify the last p2a_bands subbands band_energies
    l_band_energy_tmp[..nb].copy_from_slice(&l_band_energy[..nb]); // Q_band_energy
    let l_tmp = ener_h.max(ener_l);
    let tmp = bw_low.max(bw_high);
    let i_norm = norm_l(l_tmp);
    let j_norm = norm_s(tmp);
    let l_tmp = mult_32_16(l_shl(ener_h, i_norm), shl(bw_low, j_norm));
    let l_tmp2 = mult_32_16(l_shl(ener_l, i_norm), shl(bw_high, j_norm));
    let l_tmp2 = l_sub(l_tmp, l_tmp2);

    for i in sub(bands, p2a_bands).max(0) as usize..nb {
        let ii = i as i16;
        let mut alpha: i16;
        if sub(p2a_flags[i], 1) == 0 || l_tmp2 > 0 {
            let mut tmp = sub(bands, p2a_bands);
            tmp = sub(tmp, lowband);
            let mut exp: i16 = 0;
            let tmp1 = calc_inv(l_shl(ep_avrg, 1), &mut exp); // inline in the reference
            let l_tmp = mult_32_16(ep_tmp[i], tmp1);
            let l_tmp = mult_32_16(l_tmp, tmp);
            let l_tmp = mult_32_16(l_tmp, 16384);
            let l_tmp = l_shl(l_tmp, sub(32, exp));
            let tmp = extract_l(l_tmp.min(6554));
            let l_tmp = mult_32_16(ep_vari, tmp1);
            let l_tmp = mult_32_16(l_tmp, tmp);
            let l_tmp = l_shl(l_tmp, sub(15, exp));
            let tmp = extract_l(l_shr(l_tmp.min(13107), 1));
            alpha = add(tmp, 16384);
        } else {
            alpha = 16384;
        }

        if add(sub(ii, bands), p2a_bands) > 0 {
            let mut tmp = sub(bands, p2a_bands);
            // the reference reads last_bitalloc_max_band[i - (bands - p2a_bands + 1)]: inside
            // its two entries for every configuration's p2a_bands (<= 3); a wider one reads 0
            let flag = last_bitalloc_max_band
                .get(sub(ii, add(tmp, 1)) as usize)
                .copied()
                .unwrap_or(0);
            if sub(flag, 1) == 0 {
                tmp = sub(tmp, lowband);
                let l_tmp = mult_32_16(ep_tmp[i], tmp);
                let mut exp: i16 = 0;
                let tmp = calc_inv(l_shl(l_tmp, 16), &mut exp);
                let l_tmp = mult_32_16(ep_avrg, tmp);
                let l_tmp = l_shl(l_tmp, sub(14, exp));
                let tmp = extract_l(l_tmp.clamp(16384, 20480));
                let l_tmp = l_mult(alpha, tmp);
                alpha = extract_l(l_shr(l_tmp, 15));
            } else {
                tmp = sub(tmp, lowband);
                let mut exp: i16 = 0;
                let tmp1 = calc_inv(l_shl(ep_avrg, 1), &mut exp); // inline in the reference
                let l_tmp = mult_32_16(ep_tmp[i], tmp1);
                let l_tmp = mult_32_16(l_tmp, tmp);
                let l_tmp = l_shl(l_tmp, sub(29, exp));
                let tmp = extract_l(l_tmp.clamp(13926, 16384));
                let l_tmp = l_mult(alpha, tmp);
                alpha = extract_l(l_shr(l_tmp, 15));
            }
        }
        let l_tmp = mult_32_16(l_band_energy_tmp[i], alpha);
        l_band_energy_tmp[i] = l_shl(l_tmp, 1);
    }

    lowband = 6;
    let mut ep_avrg: i32 = 0;
    let mut ep_avrg_l: i32 = 0;
    let mut ep_peak: i32 = 0;
    for i in 0..nb {
        if sub(i as i16, lowband) >= 0 {
            ep_avrg = l_add(ep_avrg, ep_tmp[i]);
        } else {
            ep_avrg_l = l_add(ep_avrg_l, ep_tmp[i]);
            if l_sub(ep_tmp[i], ep_peak) > 0 {
                ep_peak = l_add(ep_tmp[i], 0);
            }
        }
    }

    let l_tmp = mult_32_16(ep_peak, 24576);
    let l_tmp2 = mult_32_16(ep_peak, 19661);
    let l_tmp3 = mult_32_16(ep_avrg_l, 24576);
    if (l_sub(l_shr(ep_avrg_l, 1), ep_avrg) > 0
        && l_sub(l_tmp, l_shr(ep_avrg_l, 2)) > 0
        && l_sub(l_shr(ep_avrg_l, 1), l_tmp2) < 0)
        || (l_sub(l_shr(ep_avrg, 1), ep_avrg_l) > 0
            && l_sub(l_shr(ep_avrg, 3), l_tmp3) < 0
            && l_sub(l_tmp, l_shr(ep_avrg_l, 2)) > 0)
    {
        adjust_flag = 1;
        for i in 0..lowband as usize {
            let mut exp: i16 = 0;
            let tmp = calc_inv(l_shl(ep_avrg_l, 1), &mut exp);
            let l_tmp = mult_32_16(ep_peak, tmp);
            let l_tmp = mult_32_16(l_tmp, lowband);
            let l_tmp = l_shl(l_tmp, sub(28, exp));
            let tmp = extract_l(l_tmp.min(19661));
            let l_tmp = mult_32_16(l_band_energy_tmp[i], tmp);
            l_band_energy_tmp[i] = l_shl(l_tmp, 1);
        }
    }

    hq2_bit_alloc(
        &l_band_energy_tmp,
        bands,
        l_rk,
        bit_budget,
        p2a_flags,
        p.bit_alloc_weight,
        p.band_width,
        p.num_bits,
        p.hqswb_clas,
        st.bwidth,
        p.is_transient,
    );
    WbSplit {
        adjust_flag,
        bw_low,
        bw_high,
        ener_l,
        ener_h,
    }
}

/// The envelope-adaptive bit allocation of [`hq_lr_dec`]: the NB / WB envelope adjustments, the
/// harmonic SWB allocation, or the plain `hq2_bit_alloc_fx`. The low/high band split is the
/// reference's defaults (`bw_low` 0, `bw_high` 20, no energies) unless the WB branch measured it.
fn hq_lr_dec_bit_alloc(
    st: &mut DecoderState,
    p: &AllocParams<'_>,
    inner_frame: i16,
    swb_lr: bool,
    l_bwe_br: i32,
    shape: &mut BandShape,
    l_band_energy: &[i32],
    p2a_flags: &mut [i16; BANDS],
    l_rk: &mut [i32; BANDS],
    bit_budget: &mut i16,
    last_bitalloc_max_band: &mut [i16; 2],
) -> WbSplit {
    let mut split = WbSplit {
        adjust_flag: 0,
        bw_low: 0,
        bw_high: 20,
        ener_l: 0,
        ener_h: 0,
    };
    if p.is_transient == 0
        && sub(inner_frame, L_FRAME8K) == 0
        && l_sub(st.core_brate, i32::from(HQ_13K20)) <= 0
    {
        split.adjust_flag = hq_lr_dec_alloc_nb(
            st,
            p,
            shape,
            l_band_energy,
            p2a_flags,
            l_rk,
            bit_budget,
            last_bitalloc_max_band,
        );
    } else if p.is_transient == 0 && sub(inner_frame, L_FRAME16K) == 0 {
        split = hq_lr_dec_alloc_wb(
            st,
            p,
            shape,
            l_band_energy,
            p2a_flags,
            l_rk,
            bit_budget,
            last_bitalloc_max_band,
        );
    } else if swb_lr && sub(p.hqswb_clas, HQ_HARMONIC) == 0 {
        hq2_bit_alloc_har(
            l_band_energy,
            *bit_budget,
            p.bands,
            l_rk,
            p.p2a_bands,
            l_bwe_br,
            p2a_flags,
            p.band_width,
        );
    } else {
        hq2_bit_alloc(
            l_band_energy,
            p.bands,
            l_rk,
            bit_budget,
            p2a_flags,
            p.bit_alloc_weight,
            p.band_width,
            p.num_bits,
            p.hqswb_clas,
            st.bwidth,
            p.is_transient,
        );
    }
    split
}

/// `hq_lr_dec_fx`: the HQ low-rate (LR-MDCT) decoding of one frame of `num_bits` bits into the
/// transform-domain coefficients `l_yout` (Q12, `inner_frame` lines); `is_transient` gets the
/// frame's transient flag.
pub fn hq_lr_dec(
    st: &mut DecoderState,
    l_yout: &mut [i32],
    inner_frame: i16,
    num_bits: i16,
    is_transient: &mut i16,
) {
    let mut num_bits = num_bits;
    let mut l_y2 = [0i32; FRAME_MAX];
    let mut l_y2_ni = [0i32; FRAME_MAX];
    let mut inp_vector = [0i16; FRAME_MAX];
    let mut l_band_energy = [0i32; BANDS];
    let mut npulses = [0i16; BANDS];
    let mut p2a_flags = [0i16; BANDS];
    let mut prev_swb_peak_pos_tmp = [0i16; SPT];
    let mut band_start = [0i16; BANDS];
    let mut band_end = [0i16; BANDS];
    let mut band_width = [0i16; BANDS];
    let mut l_rk = [0i32; BANDS];
    let mut org_band_start = [0i16; SPT];
    let mut org_band_end = [0i16; SPT];
    let mut org_band_width = [0i16; SPT];
    let mut new_band_start = [0i16; SPT];
    let mut new_band_end = [0i16; SPT];
    let mut new_band_width = [0i16; SPT];
    let mut k_sort = [0i16; BANDS];
    let mut last_bitalloc_max_band = [0i16; 2];

    let mut flag_spt: i16 = 0;

    let l_bwe_br = l_add(st.core_brate, 0);
    let swb_lr = sub(st.bwidth, SWB) == 0
        && (l_sub(l_bwe_br, i32::from(HQ_16K40)) == 0 || l_sub(l_bwe_br, i32::from(HQ_13K20)) == 0);
    let mut hqswb_clas: i16 = 0;
    if swb_lr {
        hqswb_clas = get_next_indice(st, 2) as i16;
        num_bits = sub(num_bits, 2);
        *is_transient = 0;
        if sub(hqswb_clas, HQ_TRANSIENT) == 0 {
            *is_transient = 1;
        }
    } else {
        // decode transient flag
        *is_transient = get_next_indice(st, 1) as i16;
        num_bits = sub(num_bits, 1);
    }

    // Configure decoder for different bandwidths, bit rates, etc.
    let mut bands: i16 = 0;
    let mut length: i16 = 0;
    let mut l_qint: i32 = 0;
    let (mut eref, mut bit_alloc_weight, mut gqlevs, mut ngq) = (0i16, 0i16, 0i16, 0i16);
    let (mut p2a_bands, mut p2a_th, mut pd_thresh, mut ld_slope, mut ni_coef) =
        (0i16, 0i16, 0i16, 0i16, 0i16);
    hq2_core_configure(
        inner_frame,
        num_bits,
        *is_transient,
        &mut bands,
        &mut length,
        &mut band_width,
        &mut band_start,
        &mut band_end,
        &mut l_qint,
        &mut eref,
        &mut bit_alloc_weight,
        &mut gqlevs,
        &mut ngq,
        &mut p2a_bands,
        &mut p2a_th,
        &mut pd_thresh,
        &mut ld_slope,
        &mut ni_coef,
        l_bwe_br,
    );
    let nb = bands as usize;
    let mut highlength = band_end[nb - 1];
    let mut har_bands = bands;

    if swb_lr && *is_transient == 0 {
        // reserve bits for HQ_NORMAL2 and HQ_HARMONIC modes
        if sub(hqswb_clas, HQ_NORMAL) == 0 || sub(hqswb_clas, HQ_HARMONIC) == 0 {
            num_bits = sub(num_bits, get_usebit_npswb(hqswb_clas));
        }
        if sub(hqswb_clas, HQ_NORMAL) == 0 {
            flag_spt = 1;
        }
    }

    if swb_lr && sub(st.prev_hqswb_clas, HQ_NORMAL) != 0 {
        st.prev_swb_peak_pos.fill(0);
    }

    // Spectral energy calculation/quantization
    let ebits = band_energy_dequant(st, &mut l_band_energy, bands, l_qint, eref, *is_transient);

    // simple check: band_energy is too large, Abnormal Situation of bit errors
    // Max: 45.0(737279,Q14) at 32kHz, highest band, Min: -6.600037(-108135,Q14) at 8kHz(NB),
    // 8kbps, is_transient (-6.7f(-109772,Q14) is safty-threshold)
    for &energy in &l_band_energy[..nb] {
        if l_sub(energy, 737_279) > 0 || l_sub(energy, -109_772) < 0 {
            st.ber_detect = 1;
            set32(l_yout, 0, inner_frame);
            return;
        }
    }

    let exp_norm = norm_s(gqlevs);
    let gqbits = sub(14, exp_norm);

    // First pass bit budget for TCQ of spectral band information
    // (*num_bits) - (short) ceil (ebits) - Ngq * gqbits;
    let mut bit_budget = sub(
        sub(num_bits, ebits),
        round_word(l_shl(l_mult(ngq, gqbits), 15)),
    );

    if swb_lr {
        if sub(hqswb_clas, HQ_HARMONIC) == 0 {
            set16(&mut p2a_flags, 1, har_bands);
        } else {
            let pbits = p2a_threshold_dequant(st, &mut p2a_flags, bands, p2a_bands);
            bit_budget = sub(bit_budget, pbits);
            if sub(hqswb_clas, HQ_NORMAL) == 0 {
                return_bits_normal2(
                    &mut bit_budget,
                    &p2a_flags,
                    bands,
                    &BITS_LAGINDICES_MODENORMAL_FX,
                );
            }
        }
    } else {
        let pbits = p2a_threshold_dequant(st, &mut p2a_flags, bands, p2a_bands);
        bit_budget = sub(bit_budget, pbits);
    }

    if sub(flag_spt, 1) == 0 {
        // initalize the desired parameters for SPT
        spt_shorten_domain_band_save(
            bands,
            &band_start,
            &band_end,
            &band_width,
            &mut org_band_start,
            &mut org_band_end,
            &mut org_band_width,
        );
        spt_shorten_domain_pre(
            &band_start,
            &band_end,
            &st.prev_swb_peak_pos,
            bands,
            l_bwe_br,
            &mut new_band_start,
            &mut new_band_end,
            &mut new_band_width,
        );
        spt_shorten_domain_set_dec(
            st,
            &p2a_flags,
            &new_band_start,
            &new_band_end,
            &new_band_width,
            bands,
            &mut band_start,
            &mut band_end,
            &mut band_width,
            &mut bit_budget,
        );
    }

    // safety check in case of bit errors
    if sub(bit_budget, 2) < 0 {
        st.ber_detect = 1;
        set32(l_yout, 0, inner_frame);
        return;
    }

    let mut shape = hq_lr_dec_band_shape(&l_band_energy, &band_width, nb);

    let params = AllocParams {
        bands,
        band_start: &band_start,
        band_end: &band_end,
        band_width: &band_width,
        bit_alloc_weight,
        num_bits,
        hqswb_clas,
        is_transient: *is_transient,
        p2a_bands,
    };
    let split = hq_lr_dec_bit_alloc(
        st,
        &params,
        inner_frame,
        swb_lr,
        l_bwe_br,
        &mut shape,
        &l_band_energy,
        &mut p2a_flags,
        &mut l_rk,
        &mut bit_budget,
        &mut last_bitalloc_max_band,
    );
    let adjust_flag = split.adjust_flag;

    if bit_budget < 0 {
        st.ber_detect = 1;
        bit_budget = 0;
    }
    tcq_core_lr_dec(
        st,
        &mut inp_vector,
        bit_budget,
        bands,
        &band_start,
        &band_width,
        &mut l_rk,
        &mut npulses,
        &mut k_sort,
        &p2a_flags,
        p2a_bands,
        &last_bitalloc_max_band,
        inner_frame,
        adjust_flag,
        *is_transient,
    );

    // Denormalize the coded MDCT spectrum
    mdct_spectrum_denorm(
        &inp_vector,
        &mut l_y2,
        &band_start,
        &band_end,
        &band_width,
        &l_band_energy,
        &npulses,
        bands,
        ld_slope,
        pd_thresh,
    );

    // Apply fine gain to denormalized coded spectrum
    mdct_spectrum_fine_gain_dec(
        st,
        &mut l_y2,
        &band_start,
        &band_end,
        &k_sort,
        bands,
        l_qint,
        ngq,
        gqlevs,
        gqbits,
    );

    // restore the band information
    if sub(flag_spt, 1) == 0 {
        spt_shorten_domain_band_restore(
            bands,
            &mut band_start,
            &mut band_end,
            &mut band_width,
            &org_band_start,
            &org_band_end,
            &org_band_width,
        );
    }

    // The reference copies L_y2 into L_y2_org here and never reads the copy; not carried.

    // Inject noise into components having relatively low pulse energy per band
    let mut ni_seed = add(add(add(npulses[0], npulses[1]), npulses[2]), npulses[3]);
    let coded = add(band_end[nb - 1], 1);
    copy32(&l_y2, &mut l_y2_ni, coded);
    hq2_noise_inject(
        &mut l_y2_ni,
        &band_start,
        &band_end,
        &band_width,
        &mut shape.ep,
        &l_rk,
        &npulses,
        ni_seed,
        bands,
        0,
        split.bw_low,
        split.bw_high,
        split.ener_l,
        split.ener_h,
        &mut st.last_ni_gain,
        &mut st.last_env,
        &mut st.last_max_pos_pulse,
        &p2a_flags,
        p2a_bands,
        hqswb_clas,
        st.bwidth,
        l_bwe_br,
    );

    if swb_lr && (sub(hqswb_clas, HQ_NORMAL) == 0 || sub(hqswb_clas, HQ_HARMONIC) == 0) {
        let layout = Layout {
            bands,
            band_start: &band_start,
            band_end: &band_end,
            band_width: &band_width,
            p2a_flags: &p2a_flags,
            p2a_bands,
            length,
        };
        hq_lr_dec_swb_bwe(
            st,
            &layout,
            hqswb_clas,
            l_bwe_br,
            &l_band_energy,
            &mut l_y2,
            &l_y2_ni,
            &mut npulses,
            &mut har_bands,
            &mut highlength,
            &mut ni_seed,
            &mut prev_swb_peak_pos_tmp,
        );
    } else {
        copy32(&l_y2_ni, &mut l_y2, coded);
    }

    hq_lr_dec_update(
        st,
        &shape.ep_tmp,
        bands,
        *is_transient,
        &l_y2,
        l_yout,
        l_bwe_br,
        length,
        inner_frame,
        hqswb_clas,
        &prev_swb_peak_pos_tmp,
    );
}

/// The band layout [`hq_lr_dec_swb_bwe`] reads.
struct Layout<'a> {
    bands: i16,
    band_start: &'a [i16],
    band_end: &'a [i16],
    band_width: &'a [i16],
    p2a_flags: &'a [i16],
    p2a_bands: i16,
    length: i16,
}

/// The SWB 13.2 / 16.4 kbit/s `HQ_NORMAL` / `HQ_HARMONIC` tail of [`hq_lr_dec`]: the LR SWB
/// bandwidth extension of the high band (`preset_hq2_swb_fx`, `swb_bwe_dec_lr_fx`,
/// `post_hq2_swb_fx`), the peak positions the next frame's shortened bands centre on, and the
/// noise-filled low band copied back into `l_y2`.
// Index loops mirror the reference's walks so the two can be diffed.
#[allow(clippy::needless_range_loop)]
fn hq_lr_dec_swb_bwe(
    st: &mut DecoderState,
    layout: &Layout<'_>,
    hqswb_clas: i16,
    l_bwe_br: i32,
    l_band_energy: &[i32],
    l_y2: &mut [i32; FRAME_MAX],
    l_y2_ni: &[i32; FRAME_MAX],
    npulses: &mut [i16; BANDS],
    har_bands: &mut i16,
    highlength: &mut i16,
    ni_seed: &mut i16,
    prev_swb_peak_pos_tmp: &mut [i16; SPT],
) {
    let bands = layout.bands;
    let nb = bands as usize;
    let mut l_m = [0i32; FRAME_MAX];
    let mut lowlength: i16 = 0;
    preset_hq2_swb(
        hqswb_clas,
        layout.band_end,
        har_bands,
        layout.p2a_bands,
        layout.length,
        bands,
        &mut lowlength,
        highlength,
        &mut l_m,
    );
    swb_bwe_dec_lr(
        st,
        &l_y2[..],
        12,
        &mut l_m,
        l_bwe_br,
        bands,
        layout.band_start,
        layout.band_end,
        l_band_energy,
        14,
        layout.p2a_flags,
        hqswb_clas,
        lowlength,
        *highlength,
        *har_bands,
        layout.band_width,
        &l_y2_ni[..],
        ni_seed,
    );
    post_hq2_swb(
        &l_m,
        lowlength,
        *highlength,
        hqswb_clas,
        *har_bands,
        bands,
        layout.p2a_flags,
        layout.band_start,
        layout.band_end,
        &mut l_y2[..],
        &mut npulses[..],
    );
    if sub(hqswb_clas, HQ_NORMAL) == 0 {
        spt_swb_peakpos_tmp_save(
            &l_y2[..],
            bands,
            layout.band_start,
            layout.band_end,
            prev_swb_peak_pos_tmp,
        );
        for k in 0..SPT {
            let band = nb - SPT + k;
            if layout.p2a_flags[band] == 0 || npulses[band] == 0 {
                prev_swb_peak_pos_tmp[k] = 0;
            }
        }
    }
    copy32(&l_y2_ni[..], &mut l_y2[..], lowlength);
}

/// The end of [`hq_lr_dec`]: the SHB energy memory for bandwidth switching and the frame
/// update (`updat_prev_frm_fx`), which also writes `l_yout`.
fn hq_lr_dec_update(
    st: &mut DecoderState,
    ep_tmp: &[i32; BANDS],
    bands: i16,
    is_transient: i16,
    l_y2: &[i32],
    l_yout: &mut [i32],
    l_bwe_br: i32,
    length: i16,
    inner_frame: i16,
    hqswb_clas: i16,
    prev_swb_peak_pos_tmp: &[i16],
) {
    if !(sub(st.last_inner_frame, L_FRAME16K) >= 0 && st.bws_cnt > 0) {
        let mut k1 = sub(bands, 2);
        if sub(is_transient, 1) != 0 {
            k1 = sub(bands, 6);
        }
        let mut l_tmp: i32 = 0;
        for i in k1..bands {
            let tmp = div_s(1, sub(bands, k1));
            l_tmp = l_add(l_tmp, mult_32_16(ep_tmp[i as usize], tmp));
        }
        st.prev_ener_shb = extract_l(l_shr(l_tmp, 14));
    }
    if sub(st.last_inner_frame, L_FRAME32K) >= 0 {
        st.prev_swb_fenv.fill(st.prev_ener_shb);
    }

    updat_prev_frm(
        l_y2,
        l_yout,
        l_bwe_br,
        length,
        inner_frame,
        bands,
        st.bwidth,
        is_transient,
        hqswb_clas,
        &mut st.prev_hqswb_clas,
        &mut st.prev_swb_peak_pos,
        prev_swb_peak_pos_tmp,
        &mut st.prev_frm_hfe2,
        &mut st.prev_stab_hfe2,
        st.bws_cnt,
    );
}
