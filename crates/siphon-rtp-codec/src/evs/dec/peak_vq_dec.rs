//! Harmonic vector quantisation (HVQ) decoding of the HQ high-rate core (TS 26.442
//! `lib_dec/peak_vq_dec_fx.c`; TS 26.445 §6.2.2.3.4): noise levels, peak positions and gains, the
//! peak shapes, the PVQ-coded bands between them and the noise fill of the rest.

use crate::evs::cnst::{
    FLAGN_BITS, GAIN0_BITS, GAINI_BITS, HQ_24K40, HVQ_BWE_NOISE_BANDS, HVQ_CP_DELTA,
    HVQ_CP_HUFF_MAX_CODE, HVQ_CP_HUFF_NUM_LEN, HVQ_CP_HUFF_OFFSET, HVQ_CP_L1_LEN, HVQ_CP_L2_MAX,
    HVQ_CP_MAP_IDX_LEN, HVQ_MAX_PEAKS_24K, HVQ_MAX_PEAKS_32K, HVQ_MAX_PVQ_WORDS, HVQ_MIN_PEAKS,
    HVQ_NF_GROUPS, HVQ_NUM_SFM_24K, HVQ_PVQ_BUF_LEN, HVQ_PVQ_GAIN_BITS, HVQ_THRES_BIN_24K,
    HVQ_THRES_BIN_32K, MAX_PG_HUFFLEN, MAX_PVQ_BANDS, NB_SFM_MAX, NUM_PG_HUFFLEN, RANDOM_INITSEED,
};
use crate::evs::com::bitstream::{get_next_indice, get_next_indice_1};
use crate::evs::com::hq_tools::hvq_concat_bands;
use crate::evs::com::hvq_pvq_bitalloc::hvq_pvq_bitalloc;
use crate::evs::com::low_rate_band_att::{fine_gain_dec, fine_gain_pred};
use crate::evs::com::math_op::i_mult2;
use crate::evs::com::pvq_com::apply_gain;
use crate::evs::com::tools::{floating_point_add, random};
use crate::evs::dec::hdecnrm::huff_dec;
use crate::evs::dec::pvq_core_dec::pvq_decode_frame;
use crate::evs::dec::state::DecoderState;
use crate::evs::rom::{
    hvq_cp_huff_offset, BAND_START_HARM, DICN_FX, DICN_PG_FX, HVQ_CP_HUFF_LEN, HVQ_CP_HUFF_TAB,
    HVQ_CP_HUFF_THRES, HVQ_CP_LAYER1_MAP5, HVQ_PEAK_CB_FX, HVQ_PG_HUFF_OFFSET, HVQ_PG_HUFF_TAB,
    HVQ_PG_HUFF_THRES, PGAIN_HUFFSIZN,
};
use crate::itu::basic_ops::{
    add, l_abs, l_negate, l_shl, l_shr, l_sub, norm_l, round_word, shl, sub,
};
use crate::itu::stl2009::{i_mult, l_mult0, lshr, mpy_32_16_ss, mpy_32_32_ss};

/// 0.1 in Q15.
const PK_VQ_NOISE_DELTA: i16 = 3277;

const MAX_PEAKS: usize = HVQ_MAX_PEAKS_32K as usize;

/// `table[index]` for a table indexed by a decoded symbol the tables bound; 0 outside it, which
/// only a corrupt (never a well-formed) stream could ask for.
fn at16(table: &[i16], index: i16) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| table.get(index))
        .copied()
        .unwrap_or(0)
}

/// `hvq_dec_fx`: read the two HVQ BWE noise levels (`noise_level`, Q15) and decode the HVQ
/// spectrum into `coefsq_norm` (Q12, zeroed by the caller) with [`peak_vq_dec`]; `R` is updated
/// with the band PVQ selected, `peak_idx` / `Npeaks` receive the peak positions.
pub fn hvq_dec(
    st: &mut DecoderState,
    num_bits: i16,
    core_brate: i32,
    ynrm: &[i16],
    r: &mut [i16],
    noise_level: &mut [i16],
    peak_idx: &mut [i16],
    npeaks: &mut i16,
    coefsq_norm: &mut [i32],
    core: i16,
) {
    let mut bits = num_bits;
    for level in noise_level.iter_mut().take(HVQ_BWE_NOISE_BANDS as usize) {
        // 2-bits => max noise_level-idx = 3
        let noise_level_idx = get_next_indice(st, 2) as i16;
        // max noise_level=3*0.1 => Q15 is good enough
        *level = i_mult(noise_level_idx, PK_VQ_NOISE_DELTA);
        bits = sub(bits, 2);
    }

    // `(Word16)core_brate`: HVQ only runs at 24.4 and 32 kbit/s, both inside Word16
    peak_vq_dec(
        st,
        coefsq_norm,
        core_brate as i16,
        bits,
        ynrm,
        r,
        peak_idx,
        npeaks,
        core,
    );
}

/// The peak gains as `peak_vq_dec_fx` decodes them: the difference indices, read Huffman or
/// fixed-length coded, accumulated and clamped; returns the bits the differences took.
fn peak_vq_dec_gains(
    st: &mut DecoderState,
    vq_peaks: i16,
    flag_n: i16,
    pgain_difidx: &mut [i16; MAX_PEAKS],
) -> i16 {
    let mut hcode_l: i16 = 0;
    if flag_n != 0 {
        huff_dec(
            st,
            vq_peaks - 1,
            MAX_PG_HUFFLEN,
            NUM_PG_HUFFLEN,
            &HVQ_PG_HUFF_THRES,
            &HVQ_PG_HUFF_OFFSET,
            &HVQ_PG_HUFF_TAB,
            &mut pgain_difidx[1..],
        );
        for &difidx in pgain_difidx.iter().take(vq_peaks.max(1) as usize).skip(1) {
            hcode_l = add(hcode_l, at16(&PGAIN_HUFFSIZN, difidx));
        }
    } else {
        for difidx in pgain_difidx
            .iter_mut()
            .take(vq_peaks.max(1) as usize)
            .skip(1)
        {
            *difidx = get_next_indice(st, GAINI_BITS) as i16;
            hcode_l = add(hcode_l, GAINI_BITS);
        }
    }
    hcode_l
}

/// `peak_vq_dec_fx`: decode the HVQ spectrum into `coefs_out` (Q12, zeroed by the caller): the
/// peak count, positions (`vq_peak_idx`, `Npeaks`) and gains, the 5-coefficient peak shapes, the
/// PVQ bands that fill the gaps (one high band may be selected, marked in `R`), and a noise fill
/// of what remains below the HVQ threshold bin.
pub fn peak_vq_dec(
    st: &mut DecoderState,
    coefs_out: &mut [i32],
    brate: i16,
    num_bits: i16,
    ynrm: &[i16],
    r: &mut [i16],
    vq_peak_idx: &mut [i16],
    npeaks: &mut i16,
    core: i16,
) {
    let mut nf_gains = [0i32; HVQ_NF_GROUPS as usize];
    let mut pgain_difidx = [0i16; MAX_PEAKS];
    let mut peak_gains = [0i32; MAX_PEAKS];
    let mut res_vec = [0i16; HVQ_THRES_BIN_32K as usize];

    // Set bitrate dependent variables
    let (max_peaks, bin_th, bin_th2) = if sub(brate, HQ_24K40) == 0 {
        (
            HVQ_MAX_PEAKS_24K,
            HVQ_THRES_BIN_24K,
            HVQ_THRES_BIN_24K / HVQ_NF_GROUPS,
        )
    } else {
        (
            HVQ_MAX_PEAKS_32K,
            HVQ_THRES_BIN_32K,
            HVQ_THRES_BIN_32K / HVQ_NF_GROUPS,
        )
    };

    // Get number of peaks
    let mut vq_peaks = get_next_indice(st, 5) as i16;
    vq_peaks = sub(max_peaks, vq_peaks);
    *npeaks = vq_peaks;
    let mut diff: i16 = 5;

    // safety check in case of bit errors
    if sub(*npeaks, HVQ_MIN_PEAKS) < 0 {
        st.ber_detect = 1;
        vq_peaks = HVQ_MIN_PEAKS;
        *npeaks = HVQ_MIN_PEAKS;
    }

    // De-quantize peak positions (res_vec is zeroed whole: the reference leaves the part past
    // bin_th uninitialised, which only the 24.4 kbit/s Huffman path writes and nothing reads)
    let pos_bits = hvq_dec_pos(st, &mut res_vec, bin_th, vq_peaks);
    diff = add(diff, pos_bits);

    let mut j: i16 = 0;
    let mut i: i16 = 0;
    // safety check in case of bit errors
    while i < bin_th && j < vq_peaks {
        if res_vec[i as usize] != 0 {
            vq_peak_idx[j as usize] = i;
            j += 1;
        }
        i += 1;
    }

    // safety check in case of bit errors
    if sub(j, vq_peaks) < 0 {
        st.ber_detect = 1;
        vq_peaks = sub(j, 1);
        *npeaks = sub(j, 1);
    }

    // Huffman or differential coding
    let flag_n = get_next_indice(st, 1) as i16;

    // De-quantize peak gains
    pgain_difidx[0] = get_next_indice(st, GAIN0_BITS) as i16;
    // safety check in case of bit errors
    if sub(pgain_difidx[0], 44) > 0 {
        st.ber_detect = 1;
        pgain_difidx[0] = 44;
    }
    peak_gains[0] = DICN_PG_FX[pgain_difidx[0] as usize]; // Q12
                                                          // vq_peak_idx[0] is the caller's (zeroed) entry when no peak was found; a peak position is
                                                          // always below bin_th
    if res_vec[usize::try_from(vq_peak_idx[0])
        .unwrap_or(0)
        .min(res_vec.len() - 1)]
        < 0
    {
        peak_gains[0] = l_negate(peak_gains[0]);
    }

    let hcode_l = peak_vq_dec_gains(st, vq_peaks, flag_n, &mut pgain_difidx);

    for i in 1..vq_peaks.max(1) as usize {
        pgain_difidx[i] = add(pgain_difidx[i], sub(pgain_difidx[i - 1], 15));
        // safety check in case of bit errors
        if sub(pgain_difidx[i], 44) > 0 || pgain_difidx[i] < 0 {
            st.ber_detect = 1;
            pgain_difidx[i] = 44;
        }
        peak_gains[i] = DICN_PG_FX[pgain_difidx[i] as usize]; // Q12
        if res_vec[vq_peak_idx[i] as usize] < 0 {
            peak_gains[i] = l_negate(peak_gains[i]);
        }
    }

    // Scale up peak gains and accumulate peak energy (a mantissa/exponent pair: the dynamic
    // range is too wide for one fixed-point format)
    let mut man_e_peak: i32 = 0;
    let mut exp_e_peak: i16 = 32;
    for i in 0..vq_peaks.max(0) as usize {
        peak_gains[i] = l_shl(peak_gains[i], 2); // Q12
        let tmp = l_shl(DICN_PG_FX[pgain_difidx[i] as usize], 2);
        let exp_peak_gains = norm_l(tmp);
        let man_peak_gains = l_shl(tmp, exp_peak_gains);
        let (man_pk_enrg, _) = mpy_32_32_ss(man_peak_gains, man_peak_gains); // peak_gains square
        let exp_pk_enrg = shl(exp_peak_gains, 1); // Multiply by 2 due to squaring.
        floating_point_add(&mut man_e_peak, &mut exp_e_peak, man_pk_enrg, exp_pk_enrg);
    }
    // Number of bits used for peak gain quantization
    diff = add(diff, add(FLAGN_BITS + GAIN0_BITS, hcode_l));

    // De-quantize peaks
    for i in 0..vq_peaks.max(0) as usize {
        // peak positions are >= 2 (hvq_dec_pos keeps 0 and 1 free) and < bin_th
        let at = usize::try_from(vq_peak_idx[i] - 2).unwrap_or(0);
        let previous = i.checked_sub(1).map(|p| peak_gains[p]);
        dequant_peaks(st, &mut coefs_out[at..], peak_gains[i], previous);
        diff = add(diff, 9);
    }

    for gain in &mut nf_gains {
        let nf_gains_idx = get_next_indice(st, 5) as i16;
        *gain = l_shr(DICN_FX[nf_gains_idx as usize], 1); // nf_gains in Q14
        diff = add(diff, 5);
    }
    let pvq_bits = sub(num_bits, diff);

    peak_vq_dec_pvq(
        st, coefs_out, brate, pvq_bits, ynrm, r, man_e_peak, exp_e_peak, core,
    );

    // Noise fill unquantized coeffs with one gain per group
    let mut nf_seed = RANDOM_INITSEED;
    let mut p = 0usize;
    for gain in nf_gains {
        for _ in 0..bin_th2 {
            if coefs_out[p] == 0 {
                let white_noise = random(&mut nf_seed); // Q15
                let (acc, _) = mpy_32_16_ss(gain, white_noise); // nf_gains in Q14
                coefs_out[p] = l_shr(acc, 14 - 12); // Q12
            }
            p += 1;
        }
    }
}

/// The PVQ part of `peak_vq_dec_fx`: band count and bit allocation, the PVQ shapes and their
/// fine gains, then each band's norm and the shape written into the free (zero) coefficients of
/// `coefs_out`, from the start for the fixed bands and from its harmonic band for a selected one.
fn peak_vq_dec_pvq(
    st: &mut DecoderState,
    coefs_out: &mut [i32],
    brate: i16,
    pvq_bits: i16,
    ynrm: &[i16],
    r: &mut [i16],
    man_e_peak: i32,
    exp_e_peak: i16,
    core: i16,
) {
    let bands = MAX_PVQ_BANDS as usize;
    let gain_bits_array = [0i16; MAX_PVQ_BANDS as usize];
    let mut pvq_vector = [0i16; HVQ_PVQ_BUF_LEN as usize];
    let mut pvq_inp_vector = [0i16; HVQ_PVQ_BUF_LEN as usize];
    let mut npulses = [0i16; MAX_PVQ_BANDS as usize];
    let mut k_sort = [0i16; HVQ_MAX_PVQ_WORDS as usize];
    // only read by fine_gain_pred_fx when R is given, which it is not here (uninitialised in the
    // reference)
    let pvq_maxpulse = [0i16; HVQ_MAX_PVQ_WORDS as usize];
    let mut rk = [0i16; MAX_PVQ_BANDS as usize];
    let mut fg_pred = [0i16; NB_SFM_MAX as usize];
    let mut sel_bnds = [0i16; HVQ_NUM_SFM_24K as usize];
    let mut hvq_band_end = [0i16; MAX_PVQ_BANDS as usize];
    let mut hvq_band_start = [0i16; MAX_PVQ_BANDS as usize];
    let mut hvq_band_width = [0i16; MAX_PVQ_BANDS as usize];
    // uninitialised in the reference when no band is coded, and then never read
    let mut n_sel_bnds: i16 = 0;

    // Calculate number of PVQ bands to code and assign bits
    let pvq_bands = hvq_pvq_bitalloc(
        pvq_bits,
        i32::from(brate),
        st.bwidth,
        ynrm,
        man_e_peak,
        exp_e_peak,
        &mut rk,
        r,
        &mut sel_bnds,
        &mut n_sel_bnds,
    );

    // safety check in case of bit errors
    if pvq_bands == 0 {
        st.ber_detect = 1;
    }

    let pvq_bits = sub(pvq_bits, i_mult2(HVQ_PVQ_GAIN_BITS, pvq_bands));
    // Get band limits for concatenated PVQ target
    hvq_concat_bands(
        pvq_bands,
        &sel_bnds,
        n_sel_bnds,
        &mut hvq_band_start,
        &mut hvq_band_width,
        &mut hvq_band_end,
    );

    let count = (pvq_bands.max(0) as usize).min(bands);
    for (k, slot) in k_sort.iter_mut().enumerate().take(count) {
        *slot = k as i16;
    }

    pvq_decode_frame(
        st,
        &mut pvq_vector,
        &mut npulses,
        &mut pvq_inp_vector,
        &hvq_band_start,
        &hvq_band_end,
        &hvq_band_width,
        pvq_bands,
        &rk,
        pvq_bits,
        core,
    );

    fine_gain_pred(
        &hvq_band_start,
        &hvq_band_end,
        &hvq_band_width,
        &k_sort,
        &npulses,
        &pvq_maxpulse,
        None,
        pvq_bands,
        &mut pvq_vector,
        &mut pvq_inp_vector,
        &mut fg_pred,
        core,
    );

    fine_gain_dec(st, &k_sort, pvq_bands, &gain_bits_array, &mut fg_pred);

    apply_gain(
        &k_sort,
        &hvq_band_start,
        &hvq_band_end,
        pvq_bands,
        &fg_pred,
        &mut pvq_vector,
    );

    let mut p_pvq = 0usize;
    let mut p_out = 0usize;
    let mut p_sel = 0usize;
    for (k, &width) in hvq_band_width.iter().enumerate().take(count) {
        let pvq_norm = add(get_next_indice(st, HVQ_PVQ_GAIN_BITS) as i16, 8);

        if sub(k as i16, sub(pvq_bands, n_sel_bnds)) >= 0 {
            p_out = BAND_START_HARM[sel_bnds[p_sel] as usize] as usize;
            p_sel += 1;
        }
        let normq = DICN_FX[pvq_norm as usize]; // pvq_norm <= 31 + 8
        let mut j: i16 = 0;
        while sub(j, width) < 0 {
            // The reference runs off the end of the spectrum if the band has fewer free
            // coefficients left than its width; the band sizes HVQ codes never get near it.
            let Some(&coefficient) = coefs_out.get(p_out) else {
                break;
            };
            if l_sub(coefficient, 0) == 0 {
                // acc(Q11), normq(Q14), pvq_vector(Q12)
                let (acc, _) = mpy_32_16_ss(normq, pvq_vector[p_pvq]);
                p_pvq += 1;
                coefs_out[p_out] = l_shl(acc, 12 - 11); // Q12
                j = add(j, 1);
            }
            p_out += 1;
        }
    }
}

/// `dequant_peaks_fx`: read the codebook index of one peak shape (4 values around the peak, maybe
/// reversed) and write the scaled shape to `vect_out[0..5]` (the peak at `vect_out[2]`, Q12),
/// keeping the left neighbours a stronger previous peak (`previous`, the reference's
/// `peak_gain[-1]`) already wrote.
fn dequant_peaks(
    st: &mut DecoderState,
    vect_out: &mut [i32],
    peak_gain: i32,
    previous: Option<i32>,
) {
    let mut xq = [0i16; 4];
    let hvq_cb_rev = get_next_indice(st, 1) as i16;
    let cb_idx = get_next_indice(st, 8) as i16;

    let mut indx = shl(cb_idx, 2) as usize;
    if hvq_cb_rev != 0 {
        indx += 3;
        for value in &mut xq {
            *value = HVQ_PEAK_CB_FX[indx]; // Q15
            indx = indx.wrapping_sub(1);
        }
    } else {
        for value in &mut xq {
            *value = HVQ_PEAK_CB_FX[indx]; // Q15
            indx += 1;
        }
    }

    let abs_peak_gain = l_abs(peak_gain);
    let scaled = |x: i16| mpy_32_16_ss(peak_gain, x).0;

    if vect_out[0] == 0 {
        vect_out[0] = scaled(xq[0]); // Q12
        vect_out[1] = scaled(xq[1]);
    } else {
        // vect_out[0] is non-zero only when a previous peak wrote it (the caller zeroes the
        // spectrum), so `previous` exists; without one the reference reads before its gain array
        let abs_peak_gain1 = l_abs(previous.unwrap_or(peak_gain));
        if l_sub(abs_peak_gain1, abs_peak_gain) <= 0 {
            vect_out[0] = scaled(xq[0]);
            vect_out[1] = scaled(xq[1]);
        } else if vect_out[1] == 0 || l_sub(abs_peak_gain1, abs_peak_gain) <= 0 {
            vect_out[1] = scaled(xq[1]);
        }
    }
    vect_out[2] = peak_gain; // Q12
    vect_out[3] = scaled(xq[2]);
    vect_out[4] = scaled(xq[3]);
}

/// `hvq_dec_pos_fx`: decode the peak positions into `pos_vec[0..length]` (+1 / -1 at a peak, by
/// its sign bit), Huffman-coded distances or the sparse two-layer code; returns the bits read.
fn hvq_dec_pos(st: &mut DecoderState, pos_vec: &mut [i16], length: i16, num_peaks: i16) -> i16 {
    let mut peak_idx = [0i16; MAX_PEAKS];
    let mut delta = [0i16; MAX_PEAKS];
    let mut sign_vec = [0i16; MAX_PEAKS];
    let peaks = (num_peaks.max(0) as usize).min(MAX_PEAKS);

    let mut num_bits: i16 = 0;
    pos_vec[..length as usize].fill(0);

    let mode = get_next_indice(st, 1) as i16;
    num_bits = add(num_bits, 1);

    if mode == HVQ_CP_DELTA {
        huff_dec(
            st,
            num_peaks,
            HVQ_CP_HUFF_MAX_CODE,
            HVQ_CP_HUFF_NUM_LEN,
            &HVQ_CP_HUFF_THRES,
            &hvq_cp_huff_offset,
            &HVQ_CP_HUFF_TAB,
            &mut delta,
        );
        for &d in &delta[..peaks] {
            num_bits = add(num_bits, at16(&HVQ_CP_HUFF_LEN, d));
        }

        peak_idx[0] = sub(delta[0], HVQ_CP_HUFF_OFFSET);
        // safety check in case of bit errors
        if peak_idx[0] < 2 {
            peak_idx[0] = 2;
            st.ber_detect = 1;
        }
        for i in 1..peaks {
            peak_idx[i] = add(add(delta[i], peak_idx[i - 1]), HVQ_CP_HUFF_OFFSET);
            // safety check in case of bit errors
            if sub(peak_idx[i], HVQ_THRES_BIN_32K) >= 0 {
                peak_idx[i] = HVQ_THRES_BIN_32K - 1;
                st.ber_detect = 1;
            }
        }
        for &index in &peak_idx[..peaks] {
            // 2 <= index < HVQ_THRES_BIN_32k, the size of the caller's buffer
            pos_vec[index as usize] = 1;
        }
    } else {
        let tmp = sparse_dec_pos(st, pos_vec, length);
        num_bits = add(num_bits, tmp);
    }

    for sign in &mut sign_vec[..peaks] {
        *sign = if get_next_indice_1(st) == 0 { -1 } else { 1 };
    }
    num_bits = add(num_bits, num_peaks);

    let mut j = 0usize;
    // safety check in case of bit errors
    for value in &mut pos_vec[..length as usize] {
        if j >= peaks {
            break;
        }
        if sub(*value, 1) == 0 {
            *value = i_mult2(*value, sign_vec[j]);
            j += 1;
        }
    }

    num_bits
}

/// `sparse_dec_pos_fx`: the sparse position code: one layer-2 bit per 5-coefficient block, and
/// for each set one a 3-bit index of the block's pattern; returns the bits read.
fn sparse_dec_pos(st: &mut DecoderState, out: &mut [i16], length: i16) -> i16 {
    let mut layer2 = [0i16; HVQ_CP_L2_MAX as usize];
    out[..length as usize].fill(0);
    let mut bits: i16 = 0;

    // layer_length = (short)((float)length/HVQ_CP_L1_LEN + 0.5); 13107 is 1/5 in Q16
    let layer_length = round_word(l_mult0(length, 13107));

    for slot in &mut layer2[..layer_length as usize] {
        *slot = get_next_indice_1(st) as i16;
    }
    bits = add(bits, layer_length);

    for j in 0..layer_length {
        if sub(layer2[j as usize], 1) == 0 {
            let idx = get_next_indice(st, HVQ_CP_MAP_IDX_LEN) as usize;
            bits = add(bits, HVQ_CP_MAP_IDX_LEN);

            let mut val = HVQ_CP_LAYER1_MAP5[idx];
            // safety check in case of bit errors: out[0] and out[1] are invalid positions
            if j == 0 && sub(val, 4) > 0 {
                st.ber_detect = 1;
                val = 4;
            }
            let tmp = i_mult2(j, HVQ_CP_L1_LEN);
            let mut i = sub(i_mult2(add(j, 1), HVQ_CP_L1_LEN).min(length), 1);
            while i >= tmp {
                out[i as usize] = val & 1;
                val = lshr(val, 1);
                i -= 1;
            }
        }
    }

    bits
}
