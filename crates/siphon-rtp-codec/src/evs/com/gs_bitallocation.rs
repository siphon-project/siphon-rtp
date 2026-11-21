//! Band selection and bit allocation of the generic audio signal coder (GSC) (TS 26.442
//! `lib_com/gs_bitallocation_fx.c`; TS 26.445 §5.2.3.5.7, §6.1.1.3.3).

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    ACELP_13K20, ACELP_8K00, ACELP_9K60, AUDIO, INACTIVE, MBANDS_GN, NB, NOISE_LEVEL_SP1,
    NOISE_LEVEL_SP1A, NOISE_LEVEL_SP2, NOISE_LEVEL_SP3, WB,
};
use crate::evs::com::bitstream::brate2idx;
use crate::evs::com::math_op::i_mult2;
use crate::evs::com::tools::{copy, maximum, set16, set32};
use crate::evs::rom::{GSC_FREQ_BITS, GSC_FREQ_BITS_FX};
use crate::itu::basic_ops::{
    add, div_s, extract_l, l_add, l_mult, l_shl, l_shr, l_shr_r, l_sub, shl, shr, sub,
};

/// `GSC_freq_bits[index]`. The index is `17 · BRATE2IDX(core_brate)` plus at most 16, inside the
/// table for every rate the GSC runs at; 0 past it keeps a stray rate from panicking.
fn freq_bits(index: i16) -> i16 {
    usize::try_from(index)
        .ok()
        .and_then(|index| GSC_FREQ_BITS.get(index))
        .copied()
        .unwrap_or(0)
}

/// `GSC_freq_bits_fx[index]` (Q18), with the same bound as [`freq_bits`].
fn freq_bits_fx(index: i16) -> i32 {
    usize::try_from(index)
        .ok()
        .and_then(|index| GSC_FREQ_BITS_FX.get(index))
        .copied()
        .unwrap_or(0)
}

/// The outputs of [`bands_and_bit_alloc`] that are not buffers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GscAllocation {
    /// `*nb_subbands`: number of bands coded.
    pub nb_subbands: i16,
    /// `*pvq_len`: number of bins those bands cover.
    pub pvq_len: i16,
}

/// `bands_and_bit_alloc_fx`: the bit budget of the GSC frequency coder (`bit`, in/out), which
/// bands it codes in which order (`max_ener_band`) and the bits of each (`out_bits_per_bands`,
/// Q3). `concat` is the encoder's `(exc_diff, concat_in)` pair, `None` in the decoder. The C's
/// `*pvq_len` is only ever overwritten, so it is returned rather than passed in.
pub fn bands_and_bit_alloc(
    cor_strong_limit: i16,
    noise_lev: i16,
    core_brate: i32,
    diff_len: i16,
    bits_used: i16,
    bit: &mut i16,
    ener_per_bd_i_q: &[i16],
    max_ener_band: &mut [i16],
    out_bits_per_bands: &mut [i16],
    concat: Option<(&[i16], &mut [i16])>,
    coder_type: i16,
    bwidth: i16,
    gsc_noisy_speech: i16,
) -> GscAllocation {
    let mut ener_vec = [0i16; MBANDS_GN as usize]; // Q12
    let mut nb_tot_bands: i16 = 16;
    let mut ener_per_bd_i_q_tmp = [0i16; MBANDS_GN as usize];
    let mut bits_per_bands = [0i32; MBANDS_GN as usize];
    let mut etmp: i16 = 0;
    let nb_bands: i16;

    copy(ener_per_bd_i_q, &mut ener_per_bd_i_q_tmp, MBANDS_GN);
    set32(&mut bits_per_bands, 0, MBANDS_GN);
    set16(out_bits_per_bands, 0, MBANDS_GN);

    // To adapt current energy band to PVQ freq band for sorting
    ener_vec[0] = add(ener_per_bd_i_q[0], ener_per_bd_i_q[1]); // Q12
    copy(&ener_per_bd_i_q_tmp[1..], &mut ener_vec, 15); // Q12
    ener_vec[15] = ener_vec[14];

    // Determination of the number of bits available to the frequency domain
    // Allocation of a maximum number of band to be encoded
    let nb_bands_max = nb_tot_bands;
    let bit_new_bands: i16 = 5;

    let bit_index = i_mult2(brate2idx(core_brate), 17);
    let bit_index_mem = bit_index;

    // *bit = (short)(core_brate*(1.0f/50) + 0.5f) - bits_used - ...
    let l_tmp = mult_32_16(core_brate, 20971);
    let tmp = extract_l(l_shr_r(l_tmp, 5));
    if (sub(coder_type, AUDIO) == 0 || sub(coder_type, INACTIVE) == 0) && sub(bwidth, NB) == 0 {
        if l_sub(core_brate, i32::from(ACELP_9K60)) >= 0 {
            *bit = sub(sub(tmp, bits_used), 25);
        } else {
            *bit = sub(sub(tmp, bits_used), 21);
        }
        nb_tot_bands = 10;
    } else {
        *bit = sub(sub(tmp, bits_used), freq_bits(bit_index));
    }

    if sub(gsc_noisy_speech, 1) == 0 {
        let swb_bit_budget = *bit;
        nb_bands = 5;

        set32(&mut bits_per_bands, 0, MBANDS_GN);
        // bit_fracf = (1.0f/nb_bands)*(SWB_bit_budget);
        let bit_fracf = l_mult(div_s(1, nb_bands), shl(swb_bit_budget, 2)); // Q18

        nb_tot_bands = sub(nb_bands_max, 6);
        nb_tot_bands = nb_tot_bands.min(16);

        for j in 0..2 {
            max_ener_band[j] = j as i16;
            ener_vec[j] = 0;
        }
        for slot in max_ener_band.iter_mut().take(nb_bands as usize).skip(2) {
            let i = maximum(&ener_vec, nb_tot_bands, &mut etmp);
            *slot = i;
            ener_vec[i as usize] = 0;
        }

        set32(&mut bits_per_bands, bit_fracf, nb_bands);
    } else {
        let mut alloc = Allocation {
            ener_vec: &mut ener_vec,
            bits_per_bands: &mut bits_per_bands,
            max_ener_band,
            nb_tot_bands,
            nb_bands_max,
            bit_index,
        };
        nb_bands = bands_and_bit_alloc_per_band(
            &mut alloc,
            cor_strong_limit,
            noise_lev,
            core_brate,
            diff_len,
            *bit,
            bit_new_bands,
            bit_index_mem,
            coder_type,
            bwidth,
        );
    }

    bands_and_bit_alloc_verify(&mut bits_per_bands, out_bits_per_bands, nb_bands, *bit);

    // Recompute the real number/length of frequency bands to encode
    let nb_subbands = nb_bands;
    let pvq_len = shl(nb_subbands, 4);

    // Concatenate bands (encoder only)
    if let Some((exc_diff, concat_in)) = concat {
        for j in 0..nb_bands {
            let from = shl(max_ener_band[j as usize], 4) as usize;
            copy(&exc_diff[from..], &mut concat_in[shl(j, 4) as usize..], 16);
        }
    }

    GscAllocation {
        nb_subbands,
        pvq_len,
    }
}

/// The state the per-band allocation shares with [`bands_and_bit_alloc`].
struct Allocation<'a> {
    ener_vec: &'a mut [i16; MBANDS_GN as usize],
    bits_per_bands: &'a mut [i32; MBANDS_GN as usize],
    max_ener_band: &'a mut [i16],
    nb_tot_bands: i16,
    nb_bands_max: i16,
    bit_index: i16,
}

/// The `GSC_noisy_speech == 0` branch of `bands_and_bit_alloc_fx`: the number of bands, their
/// order and their bits (Q18); returns `nb_bands`.
fn bands_and_bit_alloc_per_band(
    alloc: &mut Allocation<'_>,
    cor_strong_limit: i16,
    noise_lev: i16,
    core_brate: i32,
    diff_len: i16,
    bit: i16,
    bit_new_bands: i16,
    bit_index_mem: i16,
    coder_type: i16,
    bwidth: i16,
) -> i16 {
    let nb_tot_bands = alloc.nb_tot_bands;
    let mut etmp: i16 = 0;

    alloc.bit_index += 1;
    let mut bit_tmp = sub(bit, freq_bits(alloc.bit_index));
    alloc.bit_index += 1;
    let mut nb_bands_max = add(alloc.nb_bands_max, freq_bits(alloc.bit_index));
    alloc.bit_index += 1;

    let mut pvq_len: i16 = 112;
    let mut st_band: i16 = 7;

    if l_sub(core_brate, i32::from(ACELP_9K60)) <= 0 {
        pvq_len = 80;
        st_band = 5;
        if diff_len == 0 {
            nb_bands_max = add(nb_bands_max, 2);
            bit_tmp = sub(bit_tmp, 13);
        }
    } else if diff_len == 0 {
        nb_bands_max = add(nb_bands_max, 2);
        bit_tmp = sub(bit_tmp, 17);
    }

    let mut nb_bands = shr(pvq_len, 4);

    // Ajustement of the maximum number of bands in function of the dynamics of the spectrum
    // (more or less speech like)
    if sub(coder_type, INACTIVE) == 0 || sub(noise_lev, NOISE_LEVEL_SP3) >= 0 {
        // Probably classification error -> concentrate bits on LF
        nb_bands_max = nb_bands;
        if l_sub(core_brate, i32::from(ACELP_8K00)) >= 0 {
            nb_bands_max = add(nb_bands, 1);
        }
    } else if sub(noise_lev, NOISE_LEVEL_SP2) >= 0
        || (l_sub(core_brate, i32::from(ACELP_13K20)) <= 0
            && l_sub(core_brate, i32::from(ACELP_9K60)) >= 0
            && cor_strong_limit == 0)
    {
        // Very low dynamic, tend to speech, do not try to code HF at all
        nb_bands_max = sub(nb_bands_max, 2);
    } else if sub(noise_lev, NOISE_LEVEL_SP1) >= 0 {
        // Very low dynamic, tend to speech, code less HF
        nb_bands_max = sub(nb_bands_max, 1);
    }

    if sub(bwidth, NB) == 0 && sub(nb_bands_max, 10) > 0 {
        nb_bands_max = 10;
    }

    // Find extra number of band to code according to bit rate availables
    while sub(bit_tmp, bit_new_bands) >= 0 && sub(nb_bands, sub(nb_bands_max, 1)) <= 0 {
        bit_tmp = sub(bit_tmp, bit_new_bands);
        nb_bands = add(nb_bands, 1);
    }

    // Fractional bits to distribute on the first x bands
    let bit_fracf = l_mult(div_s(1, st_band), shl(bit_tmp, 2)); // Q18

    // Complete the bit allocation per frequency band
    let mut imax: i16 = 5;
    if l_sub(core_brate, i32::from(ACELP_9K60)) > 0 {
        imax = 7;
    }
    for i in 0..imax as usize {
        alloc.bits_per_bands[i] = l_add(freq_bits_fx(alloc.bit_index), bit_fracf);
        alloc.bit_index = add(alloc.bit_index, 1);
    }

    if diff_len == 0 {
        alloc.bit_index = add(bit_index_mem, 10);
        for i in 0..7 {
            alloc.bits_per_bands[i] = l_add(alloc.bits_per_bands[i], freq_bits_fx(alloc.bit_index));
            alloc.bit_index = add(alloc.bit_index, 1);
        }
    }

    // Complete the bit allocation per frequency band for 16kHz high brate mode
    for j in st_band..nb_bands {
        alloc.bits_per_bands[j as usize] = l_shl(i32::from(bit_new_bands), 18);
    }

    // Compute a maximum band (band offset) for the search on maximal energy. This is function of
    // the spectral dynamic and the bitrate
    let mut bandoffset = sub(nb_tot_bands, add(nb_bands, 2));
    if sub(noise_lev, NOISE_LEVEL_SP1A) <= 0 {
        bandoffset = sub(bandoffset, 1);
    } else if (l_sub(core_brate, i32::from(ACELP_13K20)) <= 0
        && (sub(coder_type, INACTIVE) == 0 || sub(noise_lev, NOISE_LEVEL_SP3) >= 0))
        || (l_sub(core_brate, i32::from(ACELP_13K20)) <= 0
            && l_sub(core_brate, i32::from(ACELP_9K60)) >= 0
            && cor_strong_limit == 0)
    {
        bandoffset = add(bandoffset, 1);
    }
    bandoffset = bandoffset.max(0);

    // Initiazed sorted vector. For the first x bands to be included in th final sorted vector;
    // sort the remaining bands in decrease energy order
    alloc.max_ener_band[..nb_tot_bands as usize].fill(-10);
    for j in 0..st_band as usize {
        alloc.max_ener_band[j] = j as i16;
        alloc.ener_vec[j] = -10;
    }
    let mut pos = st_band;
    for j in st_band..nb_bands {
        let i = maximum(
            &alloc.ener_vec[..],
            sub(nb_tot_bands, bandoffset),
            &mut etmp,
        );
        pos = pos.max(i);
        alloc.max_ener_band[j as usize] = i;
        alloc.ener_vec[i as usize] = -10;
    }

    // re-allocate bits to the frames such that the highest band with allocated bits is higher
    // than the threshold
    if sub(sub(nb_tot_bands, bandoffset), nb_bands) > 0
        && (sub(pos, 7) > 0 && l_sub(core_brate, i32::from(ACELP_8K00)) == 0)
        && sub(bwidth, WB) == 0
    {
        let band = sub(nb_tot_bands, add(bandoffset, nb_bands));
        for j in 0..band {
            let i = maximum(
                &alloc.ener_vec[..],
                sub(nb_tot_bands, bandoffset),
                &mut etmp,
            );
            alloc.max_ener_band[add(nb_bands, j) as usize] = i;
            alloc.ener_vec[i as usize] = -10;
            alloc.bits_per_bands[add(nb_bands, j) as usize] = 1_310_720;
        }

        nb_bands = add(nb_bands, band);

        bit_tmp = i_mult2(band, 5);

        if sub(band, 2) <= 0 {
            for j in sub(st_band, 1)..nb_bands {
                alloc.bits_per_bands[j as usize] = l_add(alloc.bits_per_bands[j as usize], 262_144);
                // Q18
            }
            bit_tmp = add(bit_tmp, add(sub(nb_bands, st_band), 1));
        }

        let mut i: i16 = 0;
        let mut j: i16 = 0;
        while bit_tmp > 0 {
            alloc.bits_per_bands[j as usize] = l_sub(alloc.bits_per_bands[j as usize], 262_144); // Q18
            j = add(j, 1);
            if sub(j, sub(st_band, i)) == 0 {
                j = 0;
            }
            if j == 0 && sub(i, sub(st_band, 1)) < 0 {
                i = add(i, 1);
            }
            bit_tmp -= 1;
        }
    }

    nb_bands
}

/// The bit-sum verification of `bands_and_bit_alloc_fx`: cap each band at 112 bits and spread the
/// overage over the bands above, then convert to Q3 and hand any bits still unassigned to the top
/// bands.
fn bands_and_bit_alloc_verify(
    bits_per_bands: &mut [i32; MBANDS_GN as usize],
    out_bits_per_bands: &mut [i16],
    nb_bands: i16,
    bit: i16,
) {
    // Bit sum verification for GSC inactive at very high rate. The maximum number of bits per
    // band of length 16 is 112. Redistribute the overage bits if needed
    let mut sum_bit: i32 = 0;
    let mut j: i16 = 0;
    for i in 0..nb_bands {
        let iu = i as usize;
        let l_tmp = mult_32_16(sum_bit, 10923);
        if l_sub(bits_per_bands[iu], 29_360_128) > 0 {
            // 112 in Q18
            sum_bit = l_add(sum_bit, l_sub(bits_per_bands[iu], 29_360_128)); // Q18
            bits_per_bands[iu] = 29_360_128;
            j = add(i, 1);
        } else if l_sub(l_add(bits_per_bands[iu], l_tmp), 29_360_128) > 0 {
            // Q18
            j = add(i, 1);
        }
    }

    if sum_bit != 0 {
        let tmp = sub(nb_bands, j);
        sum_bit = mult_32_16(sum_bit, div_s(1, tmp)); // Q18
        for i in j..nb_bands {
            bits_per_bands[i as usize] = l_add(bits_per_bands[i as usize], sum_bit);
        }
    }

    // second step of bit sum verification, normally sum_bit == *bit
    let mut w_sum_bit: i16 = 0;
    for i in 0..nb_bands as usize {
        out_bits_per_bands[i] = shl(extract_l(l_shr(bits_per_bands[i], 18)), 3);
        w_sum_bit = add(w_sum_bit, out_bits_per_bands[i]); // Q3
    }
    let tmp = shl(bit, 3);
    if sub(tmp, w_sum_bit) > 0 {
        let mut i = sub(nb_bands, 1);
        while tmp > w_sum_bit {
            // At least five bands are always coded, so `i` cycles over 1..nb_bands; the guard only
            // keeps a degenerate band count from indexing before the buffer.
            if let Some(slot) = usize::try_from(i)
                .ok()
                .and_then(|i| out_bits_per_bands.get_mut(i))
            {
                *slot = add(*slot, 1 << 3);
            }
            i = sub(i, 1);
            if i == 0 {
                i = sub(nb_bands, 1);
            }
            // C `w_sum_bit += (1<<3)` in int, truncated back to Word16
            w_sum_bit = w_sum_bit.wrapping_add(1 << 3);
        }
    }
}
