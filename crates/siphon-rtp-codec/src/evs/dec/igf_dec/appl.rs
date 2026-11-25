//! `IGF_appl` of TS 26.442 `lib_dec/igf_dec.c`: apply the decoded IGF envelope to the prepared
//! IGF spectrum and write it into the MDCT spectrum (split from `igf_dec.rs` for size; the
//! function is cut at its natural seams into the `igf_appl_*` helpers).

use crate::evs::basop::mpy_32_16_1;
use crate::evs::cnst::{
    IGF_MAX_SFB, IGF_START_MN, IGF_WHITENING_OFF, IGF_WHITENING_STRONG, N_MAX_TCX,
    TCX_IMDCT_HEADROOM,
};
use crate::evs::com::basop_util::{
    basop_util_add_mant32_exp, basop_util_add_mant_exp, basop_util_divide3232_scale,
    basop_util_pow2, norm_ll_q31, sqrt16, sqrt16norm, sqrt32,
};
use crate::evs::com::igf_base::igf_common_funcs_mdct_square_spec;
use crate::evs::com::tools::{set16, set32};
use crate::evs::dec::state::{IgfGrid, IgfdecPrivateData};
use crate::itu::basic_ops::{
    add, div_s, extract_h, l_deposit_h, l_mult, l_negate, l_shl, l_shr, l_sub, mult_r, negate,
    norm_l, norm_s, round_word, shl, shr, shr_r, sub,
};
use crate::itu::stl2009::{l_add_c, l_mac_ns, StlFlags};

/// The per-SFB working arrays of `IGF_appl`.
struct ApplyScratch {
    /// `gain`: Q0 | gain read from bitstream + processing
    gain: [i16; IGF_MAX_SFB as usize],
    /// `gain_e`
    gain_e: [i16; IGF_MAX_SFB as usize],
    /// `dN`
    d_n: [i16; IGF_MAX_SFB as usize + 1],
    /// `dN_e`
    d_n_e: [i16; IGF_MAX_SFB as usize + 1],
    /// `dS`
    d_s: [i16; IGF_MAX_SFB as usize],
    /// `dS_e`
    d_s_e: [i16; IGF_MAX_SFB as usize],
}

/// The prepared spectrum and its target as `IGF_appl` receives them.
pub(super) struct ApplyIo<'a> {
    /// `spectrum`: Q31 | MDCT spectrum
    pub spectrum: &'a mut [i32],
    /// `spectrum_e`: exponent of `spectrum`
    pub spectrum_e: &'a mut i16,
    /// `igf_spec`: Q31 | prepared IGF spectrum
    pub igf_spec: &'a [i32],
    /// `igf_spec_e`: one exponent per tile
    pub igf_spec_e: &'a [i16],
    /// `virtualSpec`: Q31 | virtual IGF spectrum, used for temp flattening
    pub virtual_spec: &'a mut [i32],
    /// `virtualSpec_e`
    pub virtual_spec_e: &'a mut i16,
    /// `flag_sparse`: temp flattening indicator
    pub flag_sparse: &'a mut [i16],
    /// `infoTCXNoise`: the 16-bit array the instance keeps just before `flag_sparse`, which a
    /// negative `flag_sparse` index lands in (see [`store_flag_sparse`])
    pub info_tcx_noise: &'a mut [i16],
}

/// `flag_sparse[index] = value` for `index = line - IGF_START_MN`.
///
/// The reference does this for every line of the grid, and the TCX10 grids start below
/// `IGF_START_MN` (their first line is 82 to 256), so the index is negative there and the write
/// lands in the memory before the array: in `IGFDEC_INSTANCE` that is the end of `infoTCXNoise`,
/// which sits directly before `flag_sparse`. `IGFDecApplyMono` clears `infoTCXNoise` right after
/// this runs, so the stray write never survives, but it is mirrored so that no state differs
/// in between and so that a reader of the old index sees what the reference sees.
fn store_flag_sparse(io: &mut ApplyIo<'_>, index: i32, value: i16) {
    if index >= 0 {
        io.flag_sparse[index as usize] = value;
    } else {
        let at = io.info_tcx_noise.len() as i32 + index;
        io.info_tcx_noise[at as usize] = value;
    }
}

/// `virtualSpec[index] = value` for `index = line - IGF_START_MN`; a negative index is the same
/// out-of-bounds write as in [`store_flag_sparse`], here into the end of `flag_sparse`, which sits
/// directly before `virtualSpec`: element `index` is the little-endian pair
/// `flag_sparse[len + 2 * index]` (low half), `flag_sparse[len + 2 * index + 1]` (high half).
/// Unlike `infoTCXNoise` nothing clears that part of `flag_sparse` after the call, and no line
/// the decoder reads (`line - IGF_START_MN` that large) can see it; it is part of the state the
/// reference leaves behind and is mirrored for that reason.
fn store_virtual_spec(io: &mut ApplyIo<'_>, index: i32, value: i32) {
    if index >= 0 {
        io.virtual_spec[index as usize] = value;
    } else {
        let at = (io.flag_sparse.len() as i32 + 2 * index) as usize;
        io.flag_sparse[at] = value as i16;
        io.flag_sparse[at + 1] = (value >> 16) as i16;
    }
}

/// The energy of the 24 lines below `startLine`, as `dE` with its exponent `dE_e`
/// (`sqrt(energy / 24)`).
fn igf_appl_energy_below_start(grid: &IgfGrid, spectrum: &[i32], spectrum_e: i16) -> (i16, i16) {
    let mut energy_tmp = [0i32; 24];
    let mut d_e_exp: i16 = 0;
    let mut flags = StlFlags::default();

    // collect energy below hGrid->startLine:
    let tmp = sub(grid.start_line, 24);
    igf_common_funcs_mdct_square_spec(
        tmp,
        grid.start_line,
        spectrum,
        spectrum_e,
        &mut energy_tmp,
        &mut d_e_exp,
        negate(tmp),
    );

    let mut l_c = 0;
    let mut l_tmp = 0;
    for energy in &energy_tmp {
        flags.carry = false; // Carry = 0
        l_tmp = l_add_c(l_tmp, *energy, &mut flags);
        flags.overflow = false; // Overflow = 0
        l_c = l_mac_ns(l_c, 0, 0, &mut flags);
    }
    let mut shift = 0;
    l_tmp = norm_ll_q31(l_c, l_tmp, &mut shift, &mut flags);
    // float: dE = (float)sqrt(dE / 24.f); basop:
    shift = add(sub(shift, 4), d_e_exp); // x/24 = (x >> 4) * 1/1.5
    let d_e = sqrt16norm(extract_h(l_tmp), &mut shift);
    // 0.81649658092772603273242802490196f = sqrt(1/1.5)
    (mult_r(d_e, 26755), shift)
}

/// Merge the SFB energies `sN` / `pN` over groups of `hopsize` bands into the first band of each
/// group, for the envelope refinement of a hopsize above one.
fn igf_appl_merge_energies(
    private: &mut IgfdecPrivateData,
    start_sfb: i16,
    stop_sfb: i16,
    hopsize: i16,
) {
    let mut sfb = start_sfb;
    while sfb < stop_sfb {
        let tmp_loop = add(sfb, hopsize).min(stop_sfb);
        for tb in add(sfb, 1)..tmp_loop {
            let (sfb, tb) = (sfb as usize, tb as usize);
            let mut exponent = 0;
            private.igf_s_n[sfb] = basop_util_add_mant32_exp(
                private.igf_s_n[sfb],
                private.igf_s_n_e[sfb],
                private.igf_s_n[tb],
                private.igf_s_n_e[tb],
                &mut exponent,
            );
            private.igf_s_n_e[sfb] = exponent;
            private.igf_p_n[sfb] = basop_util_add_mant32_exp(
                private.igf_p_n[sfb],
                private.igf_p_n_e[sfb],
                private.igf_p_n[tb],
                private.igf_p_n_e[tb],
                &mut exponent,
            );
            private.igf_p_n_e[sfb] = exponent;
            private.igf_s_n[tb] = 0;
            private.igf_p_n[tb] = 0;
        }
        sfb += hopsize;
    }
}

/// The new SFB level `dN` (mantissa, exponent) of one band or band pair (`IGF_rescale_SCF`): the
/// bitstream level `igf_curr` as a power of two, less the survived energy `s_n_local` of
/// `width_raw` lines per line, floored at `0.001 * s_n_local`, square-rooted.
fn igf_appl_scf_level(
    igf_curr: i16,
    s_n_local: i32,
    s_n_local_e: i16,
    width_raw: i16,
) -> (i16, i16) {
    // calculate and normalize the width of the current sfb
    let mut shift = norm_s(width_raw);
    let width = shl(width_raw, shift);
    let width_e = sub(15, shift); // initial value of width_e is 15, -> width = 15Q0

    // float: gn = 0.25f * igf_curr - 4.f; basop:
    let mut gn = igf_curr;
    let gn_e = 13; // set exponent of igf_curr to 13 = 15 - 2; -> igf_curr = igf_curr * 0.25, virtual division by 4
    gn = sub(gn, 16); // 13Q2 | 4 = 16 * 2^(-15 + 13); ("4" has same exponent as igf_curr now)

    // float: tmp = pow(2.f, gn); basop:
    let mut l_tmp_e = 0;
    let mut l_tmp = basop_util_pow2(l_deposit_h(gn), gn_e, &mut l_tmp_e);

    // float: tmp = tmp * tmp; basop:
    let tmp = round_word(l_tmp);
    l_tmp = l_mult(tmp, tmp);
    l_tmp_e = add(l_tmp_e, l_tmp_e);

    // float: sNlocal /= width; basop:
    shift = sub(norm_l(s_n_local), 1); // leave MSB empty, so in the division sNlocal is always smaller than width
    let s_n_local_d =
        crate::itu::basic_ops::l_deposit_h(div_s(extract_h(l_shl(s_n_local, shift)), width));
    let s_n_local_e = sub(sub(s_n_local_e, shift), width_e);

    // float: tmp  = max(0.001 * sNlocal, tmp - sNlocal); basop:
    // float: tmp = tmp - sNlocal
    let mut exponent = 0;
    l_tmp = basop_util_add_mant32_exp(
        l_tmp,
        l_tmp_e,
        l_negate(s_n_local_d),
        s_n_local_e,
        &mut exponent,
    );
    l_tmp_e = exponent;

    // max(0.001 * sNlocal, L_tmp)
    // Build a threshold and compare with L_tmp.
    // Build negated threshold and compare with negated L_tmp to cover also fullscale L_tmp case
    let mut l_tmp2 = l_shl(
        l_negate(mpy_32_16_1(s_n_local_d, 33 /* 0.001f Q15 */)),
        sub(s_n_local_e, l_tmp_e),
    );
    l_tmp2 = l_sub(l_tmp2, l_negate(l_tmp));

    if l_tmp2 < 0 {
        l_tmp = mpy_32_16_1(s_n_local_d, 33 /* 0.001f Q15 */);
        l_tmp_e = s_n_local_e;
    }

    // calc square root of L_tmp and store result in dN
    l_tmp = sqrt32(l_tmp, &mut l_tmp_e);
    (round_word(l_tmp), l_tmp_e)
}

/// The per-band levels `dN` of every band in `start_sfb..stop_sfb` (`IGF_rescale_SCF`), with the
/// envelope pairwise refined when the grid is.
fn igf_appl_rescale_scf(
    private: &IgfdecPrivateData,
    grid: &IgfGrid,
    scratch: &mut ApplyScratch,
    start_sfb: i16,
    stop_sfb: i16,
) {
    if grid.info_is_refined != 0 {
        let mut sfb = start_sfb;
        while sfb < stop_sfb {
            let u = sfb as usize;
            // get sNlocal | float: sNlocal = sN[ sfb ] + sN[ sfb+ 1 ]; basop:
            let mut s_n_local_e = 0;
            let s_n_local = basop_util_add_mant32_exp(
                private.igf_s_n[u],
                private.igf_s_n_e[u],
                private.igf_s_n[u + 1],
                private.igf_s_n_e[u + 1],
                &mut s_n_local_e,
            );
            let (level, level_e) = igf_appl_scf_level(
                private.igf_curr[shr(sfb, 1) as usize],
                s_n_local,
                s_n_local_e,
                sub(grid.swb_offset[u + 2], grid.swb_offset[u]),
            );
            scratch.d_n[u] = level;
            scratch.d_n_e[u] = level_e;
            scratch.d_n[u + 1] = scratch.d_n[u];
            scratch.d_n_e[u + 1] = scratch.d_n_e[u];
            sfb += 2;
        }
    } else {
        for sfb in start_sfb..stop_sfb {
            let u = sfb as usize;
            let (level, level_e) = igf_appl_scf_level(
                private.igf_curr[u],
                private.igf_s_n[u],
                private.igf_s_n_e[u],
                sub(grid.swb_offset[u + 1], grid.swb_offset[u]),
            );
            scratch.d_n[u] = level;
            scratch.d_n_e[u] = level_e;
        }
    }
}

/// The smoothed levels `dS` from `dN` and the core energy `dE` below the IGF start, with the first
/// band adapted to the core and the last one attenuated.
fn igf_appl_smooth_levels(
    grid: &IgfGrid,
    scratch: &mut ApplyScratch,
    start_sfb: i16,
    stop_sfb: i16,
    hopsize: i16,
    d_e: i16,
    d_e_exp: i16,
) {
    let w0: i16 = 6586; // float value: 0.201f
    let w1: i16 = 12747; // float value: 0.389f
    let w2: i16 = 13435; // float value: 0.410f
    let (s, e) = (start_sfb as usize, stop_sfb as usize);
    let mut tmp: i16 = 0;

    scratch.d_s[s] = scratch.d_n[s];
    scratch.d_s_e[s] = scratch.d_n_e[s];

    // first value with adaption to core energy:
    let tmp_e = basop_util_add_mant_exp(
        d_e,
        d_e_exp,
        negate(scratch.d_n[s]),
        scratch.d_n_e[s],
        &mut tmp,
    ); // float: tmp = dE - dN[start_sfb]
    if tmp < 0 {
        // float: dS[start_sfb] = dN[start_sfb] + fFactor * (dE-dN[start_sfb]); basop:
        let l_tmp = l_mult(grid.f_factor, tmp);
        let l_tmp_e = add(tmp_e, 1); // 1Q14 | fFactor is 1Q14
        let mut mantissa = 0;
        scratch.d_s_e[s] = basop_util_add_mant_exp(
            scratch.d_n[s],
            scratch.d_n_e[s],
            round_word(l_tmp),
            l_tmp_e,
            &mut mantissa,
        );
        scratch.d_s[s] = mantissa;
    }
    // last value with less energy:
    scratch.d_s[e - 1] = mult_r(grid.l_factor, scratch.d_n[e - 1]);
    scratch.d_s_e[e - 1] = add(scratch.d_n_e[e - 1], 1); // 1Q14 | lFactor is 1Q14

    let sfb_p1 = add(start_sfb, 1);
    let sfb_m1 = sub(stop_sfb, 1);
    if grid.info_is_refined != 0 && sub(hopsize, 1) == 0 {
        // apply filter to absolute energy values:
        for sfb in sfb_p1..sfb_m1 {
            let u = sfb as usize;
            // float: dS[sfb] = w0 * dN[sfb-1] + w1 * dN[sfb+0] + w2 * dN[sfb+1]; basop:
            let l_tmp = l_mult(w0, scratch.d_n[u - 1]);
            scratch.d_s[u] = round_word(l_tmp);
            scratch.d_s_e[u] = scratch.d_n_e[u - 1]; // w0 is Q15, so no need to add an exponent
            let l_tmp = l_mult(w1, scratch.d_n[u]);
            scratch.d_s_e[u] = basop_util_add_mant_exp(
                scratch.d_s[u],
                scratch.d_s_e[u],
                round_word(l_tmp),
                scratch.d_n_e[u], // w1 is Q15, so no need to add an exponent
                &mut tmp,
            );
            scratch.d_s[u] = tmp;
            let l_tmp = l_mult(w2, scratch.d_n[u + 1]);
            scratch.d_s_e[u] = basop_util_add_mant_exp(
                scratch.d_s[u],
                scratch.d_s_e[u],
                round_word(l_tmp),
                scratch.d_n_e[u + 1], // w2 is Q15, so no need to add an exponent
                &mut tmp,
            );
            scratch.d_s[u] = tmp;
        }
    } else {
        for sfb in sfb_p1..sfb_m1 {
            let u = sfb as usize;
            scratch.d_s[u] = scratch.d_n[u];
            scratch.d_s_e[u] = scratch.d_n_e[u];
        }
    }
}

/// The band gains `gain` / `gain_e` that bring the prepared IGF spectrum to the smoothed envelope,
/// per group of `hopsize` bands (and the new levels `dS` / `dN` of each group's first band).
/// Returns the headroom `Hr` the MDCT spectrum has to give up for the largest gain not to overflow.
fn igf_appl_gains(
    private: &IgfdecPrivateData,
    grid: &IgfGrid,
    scratch: &mut ApplyScratch,
    igf_spec_e: &[i16],
    spectrum_e: i16,
    hopsize: i16,
) -> i16 {
    let (start_sfb, stop_sfb) = (grid.start_sfb, grid.stop_sfb);
    let mut hr: i16 = 0;
    let mut tile_idx: i16 = -1;

    let mut sfb = start_sfb;
    while sfb < stop_sfb {
        let u = sfb as usize;
        let mut e: i32 = 0;
        let mut e_e: i16 = 0;
        let mut sum: i16 = 0;

        for tb in 0..hopsize {
            // calculate of the current sfb width
            let width = sub(
                grid.swb_offset[add(add(sfb, tb), 1).min(stop_sfb) as usize], // 15Q0 | width is Q0
                grid.swb_offset[add(sfb, tb).min(stop_sfb) as usize],
            );

            let index = add(sfb, tb).min(sub(stop_sfb, 1)) as usize;
            let tmp = scratch.d_s[index];
            let tmp_e = scratch.d_s_e[index];

            // square tmp
            let l_tmp = l_mult(tmp, tmp);
            let l_tmp_e = add(tmp_e, tmp_e);

            // mult L_tmp times width
            let l_tmp = l_mult(round_word(l_tmp), width);
            let l_tmp_e = add(l_tmp_e, 15); // 15Q0 | width is Q0

            // calculate resulting energy
            let mut energy_e = 0;
            e = basop_util_add_mant32_exp(e, e_e, l_tmp, l_tmp_e, &mut energy_e);
            e_e = energy_e;
            sum = add(sum, width); // 15Q0 | sum shares its exponent with width
        }

        // normalize sum for the following division
        let mut shift = norm_s(sum);
        sum = shl(sum, shift); // exponent of sum: sub(15, shift)

        // divide E by sum
        let mut tmp = div_s(shr(round_word(e), 1), sum); // shift E 1 bit to the right in order to make it smaller than sum
        let tmp_e = sub(add(e_e, 1), sub(15, shift)); // 15Q0 | sum is 15Q0

        // multiply the result by the hopsize
        let mut l_tmp = l_mult(tmp, hopsize);
        let mut l_tmp_e = add(tmp_e, 15); // 15Q0 | hopsize is 15Q0

        // take the square root and store the result in dS
        l_tmp = sqrt32(l_tmp, &mut l_tmp_e);
        scratch.d_s[u] = round_word(l_tmp);
        scratch.d_s_e[u] = l_tmp_e;

        // calculate the new dN
        scratch.d_n[u] = mult_r(grid.g_factor, scratch.d_s[u]);
        scratch.d_n_e[u] = add(scratch.d_s_e[u], 1); // 1Q14 | gFactor is 1Q14

        // calculate of the current sfb width
        let width = sub(grid.swb_offset[u + 1], grid.swb_offset[u]); // 15Q0 | width is Q0

        // square dN
        l_tmp = l_mult(scratch.d_n[u], scratch.d_n[u]);
        l_tmp_e = add(scratch.d_n_e[u], scratch.d_n_e[u]);

        // mult L_tmp times width
        shift = norm_l(l_tmp);
        l_tmp = l_shl(l_tmp, shift);
        l_tmp = l_mult(round_word(l_tmp), width);
        l_tmp_e = sub(add(l_tmp_e, 15), shift); // 15Q0 | width is Q0
        shift = norm_l(l_tmp);

        // store normalized result
        let d_n_local = l_shl(l_tmp, shift);
        let d_n_local_e = sub(l_tmp_e, shift);

        // gain calculation
        scratch.gain[u] = 0;
        if private.igf_p_n[u] != 0 {
            let mut s = 0;
            tmp = basop_util_divide3232_scale(d_n_local, private.igf_p_n[u], &mut s);
            s = sub(add(s, d_n_local_e), private.igf_p_n_e[u]);
            scratch.gain[u] = sqrt16(tmp, &mut s);
            scratch.gain_e[u] = s;
        }
        let sfb_p1 = add(sfb, 1);
        let sfb_m1 = add(sfb, hopsize).min(stop_sfb);
        for s_sfb in sfb_p1..sfb_m1 {
            scratch.gain[s_sfb as usize] = scratch.gain[u];
            scratch.gain_e[s_sfb as usize] = scratch.gain_e[u];
        }

        // --- check gains /spectrum exponents for possible overflows ---
        // get tile index
        if sub(grid.sfb_wrap[add(tile_idx, 1) as usize], sfb) <= 0 {
            tile_idx = add(tile_idx, 1);
        }
        // do a test multiplication with the highest possible value
        // (igf_spec occupies only the 16 LSBs)
        let l_tmp = mpy_32_16_1(0xFFFF_8000_u32 as i32, scratch.gain[u]);
        let l_tmp_e = add(igf_spec_e[tile_idx as usize], scratch.gain_e[u]);
        // check whether overflow would occur and calculate Headroom, needed
        let shift = sub(l_tmp_e, spectrum_e);
        tmp = sub(shift, sub(norm_l(l_tmp), TCX_IMDCT_HEADROOM));
        if tmp > 0 {
            hr = hr.max(tmp);
        }

        // disable rescaling if gain is smaler than 1
        // gain < 1, if norm_s(gain[sfb]) >= gain_e[sfb]
        tmp = sub(norm_s(scratch.gain[u]), scratch.gain_e[u]);
        if tmp >= 0 {
            hr = 0;
        }

        sfb += hopsize;
    }

    hr
}

/// Attenuate the gain of band `sfb` while frames are being concealed
/// (`frameLossCounter > 0`).
fn igf_appl_conceal_gain(scratch: &mut ApplyScratch, sfb: usize, frame_loss_counter: i16) {
    // normalize gain
    let tmp = norm_s(scratch.gain[sfb]);
    scratch.gain[sfb] = shl(scratch.gain[sfb], tmp);
    scratch.gain_e[sfb] = sub(scratch.gain_e[sfb], tmp);

    // gain[sfb] = min(gain[sfb], 12.f);
    // threshold, may overflow
    let tmp = shl(scratch.gain[sfb], sub(scratch.gain_e[sfb], 15 - 5)); // 10Q5 | tmp is in 10Q5

    if tmp > 384 {
        // 10Q5 | 384 = 12 in 10Q5
        scratch.gain[sfb] = 384;
        scratch.gain_e[sfb] = 10;
    }

    if sub(frame_loss_counter, 5) < 0 {
        // gain[sfb] -= gain[sfb] / 8 * hPrivateData->frameLossCounter; -> multiply with 0Q15 -> adaption of the exponent not needed
        if sub(frame_loss_counter, 1) == 0 {
            // 0Q15 | >> 3 ^= * 0.125 = 1 / 8
            scratch.gain[sfb] = sub(scratch.gain[sfb], shr_r(scratch.gain[sfb], 3));
        } else if sub(frame_loss_counter, 2) == 0 {
            // 0Q15 | >> 2 ^= * 0.25 = 2 / 8
            scratch.gain[sfb] = sub(scratch.gain[sfb], shr_r(scratch.gain[sfb], 2));
        } else if sub(frame_loss_counter, 3) == 0 {
            // 0Q15 | * 12288 ^= * 0.3750 = 3 / 8
            scratch.gain[sfb] = sub(scratch.gain[sfb], mult_r(scratch.gain[sfb], 12288));
        } else {
            // 0Q15 | >> 1 ^= * 0.5 = 4 / 8
            scratch.gain[sfb] = sub(scratch.gain[sfb], shr_r(scratch.gain[sfb], 1));
        }
    } else {
        // gain[sfb] /= 2; -> reduce exponent by 1
        scratch.gain_e[sfb] = sub(scratch.gain_e[sfb], 1);
    }
}

/// Write the gained IGF spectrum into the MDCT spectrum where it is empty, and into the virtual
/// spectrum (flagging each line `1` or `2` in `flag_sparse`) where the core coded a line.
fn igf_appl_tiling(
    private: &IgfdecPrivateData,
    grid: &IgfGrid,
    scratch: &mut ApplyScratch,
    io: &mut ApplyIo<'_>,
) {
    let mut tile_idx: i16 = -1;
    for sfb in grid.start_sfb..grid.stop_sfb {
        let u = sfb as usize;
        // get tile index
        if sub(grid.sfb_wrap[add(tile_idx, 1) as usize], sfb) == 0 {
            tile_idx = add(tile_idx, 1);
        }

        if private.frame_loss_counter > 0 {
            igf_appl_conceal_gain(scratch, u, private.frame_loss_counter);
        }

        for tb in grid.swb_offset[u]..grid.swb_offset[u + 1] {
            let tb = tb as usize;
            // multiply the prepared IGF spectrum with the gain
            let mut l_tmp2 = 0; // set L_tmp2 to default value
            let l_tmp = mpy_32_16_1(io.igf_spec[tb], scratch.gain[u]);
            let l_tmp_e = add(io.igf_spec_e[tile_idx as usize], scratch.gain_e[u]);

            // store the finalized IGF spectrum
            if io.spectrum[tb] == 0 {
                let shift = sub(l_tmp_e, *io.spectrum_e);
                // int arithmetic, stored to a Word16
                let tmp = norm_l(l_tmp).wrapping_sub(shift).wrapping_sub(32);
                if tmp < 0 {
                    l_tmp2 = l_shl(l_tmp, shift);
                }
                io.spectrum[tb] = l_tmp2;
                store_flag_sparse(io, tb as i32 - i32::from(IGF_START_MN), 1);
            } else {
                let shift = sub(l_tmp_e, *io.virtual_spec_e);
                let tmp = norm_l(l_tmp).wrapping_sub(shift).wrapping_sub(32);
                if tmp < 0 {
                    l_tmp2 = l_shl(l_tmp, shift);
                }
                store_virtual_spec(io, tb as i32 - i32::from(IGF_START_MN), l_tmp2);
                store_flag_sparse(io, tb as i32 - i32::from(IGF_START_MN), 2);
            }
        }
    }
}

/// `IGF_appl`: apply the IGF decoder. The gap-filled lines go into `io.spectrum` (lines the core
/// left empty) or `io.virtual_spec` (lines it coded, kept for the temporal flattening).
pub(super) fn igf_appl(private: &mut IgfdecPrivateData, igf_grid_idx: i16, mut io: ApplyIo<'_>) {
    let grid = private.igf_info.grid[igf_grid_idx as usize].clone();
    let (start_sfb, stop_sfb) = (grid.start_sfb, grid.stop_sfb);
    let mut scratch = ApplyScratch {
        gain: [0; IGF_MAX_SFB as usize],
        gain_e: [0; IGF_MAX_SFB as usize],
        d_n: [0; IGF_MAX_SFB as usize + 1],
        d_n_e: [0; IGF_MAX_SFB as usize + 1],
        d_s: [0; IGF_MAX_SFB as usize],
        d_s_e: [0; IGF_MAX_SFB as usize],
    };

    // reset virtual spec
    set16(io.flag_sparse, 0, N_MAX_TCX - IGF_START_MN);
    set32(io.virtual_spec, 0, N_MAX_TCX - IGF_START_MN);
    *io.virtual_spec_e = *io.spectrum_e;

    let (d_e, d_e_exp) = igf_appl_energy_below_start(&grid, io.spectrum, *io.spectrum_e);

    // select correct hopsize for envelope refinement
    let mut hopsize: i16 = 2;
    if sub(private.curr_whitening_level[0], IGF_WHITENING_OFF) == 0 {
        hopsize = 4;
    }
    if sub(private.curr_whitening_level[0], IGF_WHITENING_STRONG) == 0 {
        hopsize = 1;
    }
    hopsize = hopsize.min(private.igf_info.max_hopsize);

    if hopsize > 1 {
        igf_appl_merge_energies(private, start_sfb, stop_sfb, hopsize);
    }

    igf_appl_rescale_scf(private, &grid, &mut scratch, start_sfb, stop_sfb);
    igf_appl_smooth_levels(
        &grid,
        &mut scratch,
        start_sfb,
        stop_sfb,
        hopsize,
        d_e,
        d_e_exp,
    );

    let hr = igf_appl_gains(
        private,
        &grid,
        &mut scratch,
        io.igf_spec_e,
        *io.spectrum_e,
        hopsize,
    );

    // Rescale spectrum if overflow may occur
    if hr > 0 {
        // rescale virtual Spec, cheap and easy: reset scalingfactor
        *io.virtual_spec_e = add(*io.virtual_spec_e, hr);

        // rescale spectrum
        for line in &mut io.spectrum[..grid.stop_line as usize] {
            *line = l_shr(*line, hr);
        }
        *io.spectrum_e = add(*io.spectrum_e, hr);
    }

    // tiling
    igf_appl_tiling(private, &grid, &mut scratch, &mut io);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scf_level_of_silence_is_the_floor_of_the_gain_exponent() {
        // no survived energy: the level is sqrt(2^(2 * gn)) with gn = 0.25 * 16 - 4 = 0
        let (level, level_e) = igf_appl_scf_level(16, 0, 0, 4);
        assert_ne!(level, 0);
        assert!(level_e <= 2);
    }

    #[test]
    fn concealment_gain_is_attenuated_with_each_lost_frame() {
        let mut scratch = ApplyScratch {
            gain: [16384; IGF_MAX_SFB as usize],
            gain_e: [0; IGF_MAX_SFB as usize],
            d_n: [0; IGF_MAX_SFB as usize + 1],
            d_n_e: [0; IGF_MAX_SFB as usize + 1],
            d_s: [0; IGF_MAX_SFB as usize],
            d_s_e: [0; IGF_MAX_SFB as usize],
        };
        igf_appl_conceal_gain(&mut scratch, 0, 1);
        let first = scratch.gain[0];
        scratch.gain[1] = 16384;
        igf_appl_conceal_gain(&mut scratch, 1, 4);
        assert!(scratch.gain[1] < first);
    }
}
