//! Part of `lib_com/hq_tools_fx.c` (see the parent module): the noise-fill codebook and its
//! application, the noise-fill gain, the HQ generic fine structure and BWE with its core/BWE
//! overlap, and the envelope application (TS 26.445 §6.2.2.3.6 to §6.2.2.3.8).

use crate::evs::basop::mult_32_16;
use crate::evs::cnst::{
    HQ_24K40, HQ_32K, HQ_GEN_FB, HQ_GEN_SWB, L_FRAME16K, L_FRAME32K, PVQ_MAX_BAND_SIZE,
};
use crate::evs::com::math_op::isqrt;
use crate::evs::com::swb_bwe_com::hq_generic_decoding;
use crate::evs::com::tools::random;
use crate::evs::rom::{DICN_FX, INV_TBL_FX, SWB_BWE_SUBBAND_FX};
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_add, l_mult, l_shl, l_sub, mult_r, norm_s, shl, shr, sub,
};
use crate::itu::stl2009::{l_mac0, lshr, mpy_32_16_ss};

/// `dicn_fx[norm]` for a norm index. Norm indices come out of the envelope decoder already
/// limited to 0..=39 (and the HQ generic mapping clamps to 39); the clamp only keeps a corrupt
/// caller from indexing past the 40-entry table, where the reference would read out of bounds.
fn dicn(norm: i16) -> i32 {
    DICN_FX[norm.clamp(0, 39) as usize]
}

/// `build_nf_codebook_fx`: collect the coded coefficients of the bands with bits (up to
/// `last_sfm`) into the noise-fill codebook. With the envelope hangover flag the codebook is
/// built compressed (signs only, 8-coefficient vectors with fewer than two non-zeros dropped) in
/// `code_book_mod` and densified into `code_book`. Returns the codebook length.
pub fn build_nf_codebook(
    flag_32k_env_ho: i16,
    coeff: &[i16],
    sfm_start: &[i16],
    sfmsize: &[i16],
    sfm_end: &[i16],
    last_sfm: i16,
    r: &[i16],
    code_book: &mut [i16],
    code_book_mod: &mut [i16],
) -> i16 {
    let mut cb_size: i16 = 0;

    for sfm in 0..=last_sfm.max(-1) {
        let sfm = sfm as usize;
        if r[sfm] != 0 {
            if flag_32k_env_ho != 0 {
                // Build compressed (+/- 1) noise-fill codebook
                let sfm_base = sfm_start[sfm];
                for i in 0..sfmsize[sfm] / 8 {
                    let mut e_cb_vec: i16 = 0;
                    for j in sfm_base + i * 8..sfm_base + (i + 1) * 8 {
                        let value = coeff[j as usize];
                        code_book_mod[cb_size as usize] = if value > 0 {
                            e_cb_vec = add(e_cb_vec, 1);
                            1 << 12
                        } else if value < 0 {
                            e_cb_vec = add(e_cb_vec, 1);
                            -(1 << 12)
                        } else {
                            0
                        };
                        cb_size = add(cb_size, 1);
                    }
                    if e_cb_vec < 2 {
                        cb_size = sub(cb_size, 8);
                    }
                }
            } else {
                for j in sfm_start[sfm]..sfm_end[sfm] {
                    code_book[cb_size as usize] = coeff[j as usize];
                    cb_size = add(cb_size, 1);
                }
            }
        }
    }

    if flag_32k_env_ho != 0 {
        for j in 0..cb_size {
            let j = j as usize;
            let mirror = code_book_mod[cb_size as usize - j - 1];
            if code_book_mod[j] != 0 {
                // Densify codebook
                code_book[j] = if code_book_mod[j] > 0 { 4096 } else { -4096 };
                if mirror != 0 {
                    code_book[j] = shl(code_book[j], 1);
                }
            } else {
                code_book[j] = mirror;
            }
        }
    }

    cb_size
}

/// `apply_noisefill_HQ_fx`: fill the bands without bits (up to `last_sfm`) from the noise-fill
/// codebook, cyclically. With the hangover flag each band is normalised to unit energy, drawing
/// from the densified codebook below band 20 and the plain one above. Applies only at 32/48 kHz or
/// outside 24.4..=32 kbit/s.
pub fn apply_noisefill_hq(
    r: &[i16],
    length: i16,
    flag_32k_env_ho: i16,
    l_core_brate: i32,
    last_sfm: i16,
    code_book: &[i16],
    code_book_mod: &[i16],
    cb_size: i16,
    sfm_start: &[i16],
    sfm_end: &[i16],
    sfmsize: &[i16],
    coeff: &mut [i16],
) {
    if !(sub(length, L_FRAME32K) >= 0
        || l_sub(l_core_brate, i32::from(HQ_32K)) > 0
        || l_sub(l_core_brate, i32::from(HQ_24K40)) < 0)
    {
        return;
    }
    // Read from codebook
    let mut cb_pos: i16 = 0;
    let mut cb_buff = [0i16; PVQ_MAX_BAND_SIZE as usize];
    for sfm in 0..=last_sfm.max(-1) {
        let sfm = sfm as usize;
        if r[sfm] != 0 {
            continue;
        }
        if sub(flag_32k_env_ho, 1) == 0 {
            let source = if sub(sfm as i16, 20) < 0 {
                code_book_mod
            } else {
                code_book
            };
            let mut l_e_cb_vec: i32 = 0;
            for slot in cb_buff.iter_mut().take(sfmsize[sfm].max(0) as usize) {
                *slot = source[cb_pos as usize];
                cb_pos += 1;
                l_e_cb_vec = l_mac0(l_e_cb_vec, *slot, *slot); // Q24
                if sub(cb_pos, cb_size) >= 0 {
                    cb_pos = 0;
                }
            }

            // E_corr = E_cb_vec / sfmsize[sfm]
            let (l_e_corr, _) = mpy_32_16_ss(l_e_cb_vec, INV_TBL_FX[sfmsize[sfm] as usize]); // Q24
                                                                                             // E_corr = 1 / sqrt(E_corr)
            let l_e_corr = isqrt(l_e_corr); // Q19
            let e_corr = extract_h(l_shl(l_e_corr, 10)); // Q13

            let istart = sfm_start[sfm];
            for j in istart..sfm_end[sfm] {
                coeff[j as usize] =
                    extract_h(l_shl(l_mult(cb_buff[(j - istart) as usize], e_corr), 2));
                // Q12
            }
        } else {
            for j in sfm_start[sfm]..sfm_end[sfm] {
                coeff[j as usize] = code_book[cb_pos as usize];
                cb_pos += 1;
                if sub(cb_pos, cb_size) >= 0 {
                    cb_pos = 0;
                }
            }
        }
    }
}

/// `apply_nf_gain_fx`: scale the noise-filled bands (no bits, up to `last_sfm`) down by
/// `2^-nf_idx`.
pub fn apply_nf_gain(
    nf_idx: i16,
    last_sfm: i16,
    r: &[i16],
    sfm_start: &[i16],
    sfm_end: &[i16],
    coeff: &mut [i16],
) {
    for sfm in 0..=last_sfm.max(-1) {
        let sfm = sfm as usize;
        if r[sfm] == 0 {
            for j in sfm_start[sfm]..sfm_end[sfm] {
                // Scale NoiseFill
                coeff[j as usize] = shr(coeff[j as usize], nf_idx);
            }
        }
    }
}

/// `hq_generic_fine_fx`: the HQ generic excitation for bands `0..=last_sfm`: the coded spectrum
/// where it is non-zero, otherwise a random ±0.5 (Q12) from `bwe_seed`.
pub fn hq_generic_fine(
    coeff: &[i16],
    last_sfm: i16,
    sfm_start: &[i16],
    sfm_end: &[i16],
    bwe_seed: &mut i16,
    coeff_out1: &mut [i16],
) {
    for sfm in 0..=last_sfm.max(-1) {
        let sfm = sfm as usize;
        for i in sfm_start[sfm]..sfm_end[sfm] {
            let i = i as usize;
            coeff_out1[i] = if coeff[i] == 0 {
                if random(bwe_seed) > 0 {
                    2048
                } else {
                    -2048
                }
            } else {
                coeff[i]
            };
        }
    }
}

/// `overlap_hq_bwe_fx`: cross-fade the core spectrum `hq_swb_overlap_buf` into the BWE spectrum
/// over the `n_swb_overlap` bins from `n_swb_overlap_offset` (a plain copy when the last envelope
/// band has bits), then restore the core spectrum in every coded band above `num_env_bands`.
fn overlap_hq_bwe(
    hq_swb_overlap_buf: &[i32],
    coeff_out: &mut [i32],
    n_swb_overlap_offset: i16,
    n_swb_overlap: i16,
    r: &[i16],
    num_env_bands: i16,
    num_sfm: i16,
    sfm_end: &[i16],
) {
    let offset = n_swb_overlap_offset as usize;
    if r[sub(num_env_bands, 1) as usize] != 0 {
        let count = n_swb_overlap.max(0) as usize;
        coeff_out[offset..offset + count].copy_from_slice(&hq_swb_overlap_buf[..count]);
    } else {
        let exp = norm_s(n_swb_overlap);
        let tmp = div_s(16384, shl(n_swb_overlap, exp)); // 15 + 14 - exp
        let tmp = shr(tmp, sub(14, exp)); // 15
        let step = mult_r(tmp, 32767); // 15
        let mut weighting: i16 = 32767;
        for i in 0..n_swb_overlap.max(0) {
            let at = add(n_swb_overlap_offset, i) as usize;
            coeff_out[at] = l_add(
                coeff_out[at],
                mult_32_16(
                    l_sub(hq_swb_overlap_buf[i as usize], coeff_out[at]),
                    weighting,
                ),
            );
            weighting = sub(weighting, step);
        }
    }

    for n_band in num_env_bands..num_sfm {
        if r[n_band as usize] != 0 {
            for i in sfm_end[sub(n_band, 1) as usize]..sfm_end[n_band as usize] {
                coeff_out[i as usize] = hq_swb_overlap_buf[sub(i, n_swb_overlap_offset) as usize];
            }
        }
    }
}

/// `hq_bwe_fx`: the HQ generic BWE: keep the core spectrum above the BWE start, decode the BWE
/// spectrum from `coeff_out1` and the envelope, then overlap the two.
pub fn hq_bwe(
    hq_mode: i16,
    coeff_out1: &mut [i32],
    hq_generic_fenv: &[i16],
    coeff_out: &mut [i32],
    hq_generic_offset: i16,
    prev_l_swb_norm: &mut i16,
    hq_generic_exc_clas: i16,
    sfm_end: &[i16],
    num_sfm: i16,
    num_env_bands: i16,
    r: &[i16],
) {
    let mut hq_swb_overlap_buf = [0i32; L_FRAME32K as usize];

    let n_swb_overlap_offset = add(SWB_BWE_SUBBAND_FX[0], hq_generic_offset);
    let n_swb_overlap = sub(
        sfm_end[sub(num_env_bands, 1) as usize],
        n_swb_overlap_offset,
    );

    let count = sub(
        add(n_swb_overlap, sfm_end[sub(num_sfm, 1) as usize]),
        sfm_end[sub(num_env_bands, 1) as usize],
    )
    .max(0) as usize;
    let offset = n_swb_overlap_offset as usize;
    hq_swb_overlap_buf[..count].copy_from_slice(&coeff_out[offset..offset + count]);

    hq_generic_decoding(
        hq_mode,
        coeff_out1,
        hq_generic_fenv,
        coeff_out,
        hq_generic_offset,
        prev_l_swb_norm,
        hq_generic_exc_clas,
        r,
    );

    overlap_hq_bwe(
        &hq_swb_overlap_buf,
        coeff_out,
        n_swb_overlap_offset,
        n_swb_overlap,
        r,
        num_env_bands,
        num_sfm,
        sfm_end,
    );
}

/// `normq * coeff` as the reference rounds it: the `Mpy_32_16_ss` high word doubled, plus the top
/// bit of the low word (Q14 · Q12 → Q12).
fn scale(normq: i32, coeff: i16) -> i32 {
    let (l_tmp, lsb) = mpy_32_16_ss(normq, coeff);
    l_add(l_shl(l_tmp, 1), i32::from(lshr(lsb as i16, 15)))
}

/// `apply_envelope_fx`: apply the adjusted envelope `dicn[norm] · norm_adj` to the normalised
/// spectrum `coeff` into `coeff_out`, writing the adjusted norms to `normq_v`. At 16 kHz every band
/// is scaled; otherwise bands up to `last_sfm` for the HQ generic modes (which also scale their
/// excitation `coeff1` into `coeff_out1`) and all `num_sfm` bands for the others. At 16 kHz the
/// written norm is the unadjusted one (as in the reference).
pub fn apply_envelope(
    coeff: &[i16],
    norm: &[i16],
    norm_adj: &[i16],
    num_sfm: i16,
    last_sfm: i16,
    hq_mode: i16,
    length: i16,
    sfm_start: &[i16],
    sfm_end: &[i16],
    normq_v: &mut [i32],
    coeff_out: &mut [i32],
    coeff1: &[i16],
    coeff_out1: &mut [i32],
) {
    let generic = sub(hq_mode, HQ_GEN_SWB) == 0 || sub(hq_mode, HQ_GEN_FB) == 0;
    let mut len = num_sfm;
    if generic {
        len = add(last_sfm, 1);
    }

    if sub(length, L_FRAME16K) == 0 {
        for sfm in 0..num_sfm.max(0) as usize {
            normq_v[sfm] = dicn(norm[sfm]);
            let (normq, _) = mpy_32_16_ss(normq_v[sfm], norm_adj[sfm]); // Q14
            for i in sfm_start[sfm]..sfm_end[sfm] {
                coeff_out[i as usize] = scale(normq, coeff[i as usize]);
            }
        }
    } else {
        for sfm in 0..len.max(0) as usize {
            normq_v[sfm] = mpy_32_16_ss(dicn(norm[sfm]), norm_adj[sfm]).0; // Q14
            let normq = normq_v[sfm];
            for i in sfm_start[sfm]..sfm_end[sfm] {
                coeff_out[i as usize] = scale(normq, coeff[i as usize]);
            }
        }

        if generic {
            for sfm in 0..=last_sfm.max(-1) {
                let sfm = sfm as usize;
                let normq = normq_v[sfm];
                for i in sfm_start[sfm]..sfm_end[sfm] {
                    coeff_out1[i as usize] = scale(normq, coeff1[i as usize]);
                }
            }
        }
    }
}
