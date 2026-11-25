//! Intelligent Gap Filling decoder (TS 26.442 `lib_dec/igf_dec.c`; TS 26.445 clause 6.2.2.3.9).
//!
//! The reference passes the IGF instance (`hIGFDec`) next to the decoder state it lives in. Here
//! the functions that also read the bitstream take only the decoder state and use
//! `st.h_igf_dec`; the others take the instance. Its handle is never NULL at any call site, so the
//! reference's NULL checks are not ported. `IGF_appl` is in `appl`.

mod appl;

use crate::evs::basop::{mpy_32_16_1, mpy_32_16_r};
use crate::evs::cnst::{
    IGF_BITRATE_FB_48000, IGF_BITRATE_SWB_48000, IGF_GRID_LB_NORM, IGF_GRID_LB_SHORT,
    IGF_GRID_LB_TRAN, IGF_MAX_GRANULE_LEN, IGF_MAX_SFB, IGF_MAX_TILES, IGF_START_MX,
    IGF_WHITENING_MID, IGF_WHITENING_OFF, IGF_WHITENING_STRONG,
};
use crate::evs::com::basop_util::{divide3232, get_scale_factor32, get_sqrt_word32};
use crate::evs::com::bitstream::get_next_indice;
use crate::evs::com::igf_base::igf_common_funcs_igf_configuration;
use crate::evs::com::tools::{copy, copy32, random, set16, set32};
use crate::evs::dec::igf_scf_dec::{
    igf_scf_decoder_decode, igf_scf_decoder_open, igf_scf_decoder_reset,
};
use crate::evs::dec::state::{DecoderState, IgfGrid, IgfdecInstance, IgfdecPrivateData};
use crate::itu::basic_ops::{
    add, extract_h, extract_l, l_abs, l_add, l_deposit_l, l_mac, l_msu, l_mult, l_shl, l_shr,
    l_sub, norm_l, shl, shr, sub,
};

/// `IGF_getScaleFactor32Cond`: the headroom of the entries of `x[0..len_x]` whose `cond` is
/// non-zero, in `[0, 31]`; 0 when all of them are zero.
fn igf_get_scale_factor32_cond(cond: &[i16], x: &[i32], len_x: i16) -> i16 {
    let mut x_max: i32 = 0;
    let mut x_min: i32 = 0;

    for i in 0..len_x.max(0) as usize {
        let mut tmp32 = l_add(x[i], 0); // L_and(x[i], cond[i]);

        if cond[i] == 0 {
            tmp32 = 0; // L_deposit_h(0)
        }

        if tmp32 >= 0 {
            x_max = x_max.max(tmp32);
        }
        if tmp32 < 0 {
            x_min = x_min.min(tmp32);
        }
    }

    let mut i_max = 0x20;
    let mut i_min = 0x20;

    if x_max != 0 {
        i_max = norm_l(x_max);
    }
    if x_min != 0 {
        i_min = norm_l(x_min);
    }

    i_max.min(i_min) & 0x1F
}

/// `IGF_replaceTCXNoise_1`: measure the TCX noise lines of `in_[start..stop]` (energy into
/// `total_noise_nrg`); returns how many there are.
fn igf_replace_tcx_noise_1(
    in_: &[i32],
    s_l: i16,
    tcx_noise: &[i16],
    start: i16,
    stop: i16,
    total_noise_nrg: &mut i32,
) -> i16 {
    let mut tmp16: i16 = 0;
    let mut noise: i16 = 0;
    let s_l = sub(s_l, 5);
    let mut n_e = l_add(0, 0);

    for sb in start..stop {
        let sb = sb as usize;
        if tcx_noise[sb] != 0 {
            tmp16 = extract_h(l_shl(in_[sb], s_l));
        }
        if tcx_noise[sb] != 0 {
            n_e = l_mac(n_e, tmp16, tmp16);
        }
        if tcx_noise[sb] != 0 {
            noise = add(noise, 1);
        }
    }

    *total_noise_nrg = n_e;

    noise
}

/// `IGF_replaceTCXNoise_2`: replace the TCX noise lines of `in_[start..stop]` with random noise
/// of the energy `total_noise_nrg` measured before, scaled down by `s_l`.
fn igf_replace_tcx_noise_2(
    in_: &mut [i32],
    tcx_noise: &[i16],
    start: i16,
    stop: i16,
    total_noise_nrg: i32,
    s_l: i16,
    nf_seed: &mut i16,
) {
    let mut val: i16 = 0;
    let mut r_e = l_add(0, 0);

    for sb in start..stop {
        let sb = sb as usize;
        if tcx_noise[sb] != 0 {
            val = random(nf_seed);
        }
        if tcx_noise[sb] != 0 {
            in_[sb] = l_deposit_l(val);
        }
        if tcx_noise[sb] != 0 {
            val = shr(val, 5);
        }
        if tcx_noise[sb] != 0 {
            r_e = l_mac(r_e, val, val);
        }
    }

    let total_noise_nrg = l_shr(total_noise_nrg, 1);

    // make sure that rE is never 0
    if r_e == 0 {
        r_e = l_add(total_noise_nrg, 0); // save move32() -> use L_add(x, 0) = x;
    }

    // if totalNoiseNrg == 0, then rE must be at least 0x00010000, otherwise division by 0 will occur
    if total_noise_nrg == 0 {
        r_e = r_e.max(0x0001_0000);
    }

    // make sure that rE is never smaller than totalNoiseNrg
    let l_tmp = l_sub(r_e, total_noise_nrg);
    if l_tmp < 0 {
        r_e = l_add(total_noise_nrg, 0); // save move32() -> use L_add(x, 0) = x;
    }

    let mut g = get_sqrt_word32(l_mult(
        divide3232(total_noise_nrg, r_e),
        8192, // 1.0f / 4.0f Q15
    ));
    g = shl(g, 1);

    for sb in start..stop {
        let sb = sb as usize;
        if tcx_noise[sb] != 0 {
            in_[sb] = l_shr(l_mult(extract_l(in_[sb]), g), s_l);
        }
    }
}

/// `IGF_decode_whitening_level`: read the whitening level of tile `p`.
fn igf_decode_whitening_level(st: &mut DecoderState, p: usize) {
    let tmp = get_next_indice(st, 1);

    if tmp == 0 {
        st.h_igf_dec.igf_data.curr_whitening_level[p] = IGF_WHITENING_MID;

        return;
    }

    let tmp = get_next_indice(st, 1);
    st.h_igf_dec.igf_data.curr_whitening_level[p] = IGF_WHITENING_STRONG;

    if tmp == 0 {
        st.h_igf_dec.igf_data.curr_whitening_level[p] = IGF_WHITENING_OFF;
    }
}

/// `IGF_decode_temp_flattening_trigger`: read the temporal flattening trigger.
fn igf_decode_temp_flattening_trigger(st: &mut DecoderState) {
    st.h_igf_dec.flattening_trigger = get_next_indice(st, 1) as i16;
}

/// `IGF_setLinesToZero`: zero the power-spectrum lines `start_line..stop_line` where the original
/// MDCT spectrum has content, which the energy calculation must not count.
fn igf_set_lines_to_zero(
    start_line: i16,
    stop_line: i16,
    p_spectral_data: &[i32],
    p_power_spec_igf: &mut [i32],
) {
    for i in start_line..stop_line {
        let i = i as usize;
        if p_spectral_data[i] != 0 {
            p_power_spec_igf[i] = l_deposit_l(0);
        }
    }
}

/// `IGF_prep`: prepare the IGF spectrum `igf_spec` (one exponent per tile in `igf_spec_e`) from
/// the whitened or the LPC-flat source spectrum, per tile.
///
/// The reference receives `hPrivateData->pSpecFlat` as `src_spec` (and `pSpecFlat_exp` as
/// `src_spec_e`) from its only caller, and replaces the noise in that same buffer, so the source is
/// read from `private.p_spec_flat` here.
fn igf_prep(
    private: &mut IgfdecPrivateData,
    igf_grid_idx: i16,
    tcx_noise: &[i16],
    igf_spec: &mut [i32],
    igf_spec_e: &mut [i16],
    src_spec_e: i16,
    spec_med_e: i16,
) {
    let grid = private.igf_info.grid[igf_grid_idx as usize].clone();
    let n_noise_bands = private.n_noise_bands;
    let n_noise_bands_off = private.n_noise_bands_off;
    let total_noise_nrg = private.total_noise_nrg;
    let total_noise_nrg_off = private.total_noise_nrg_off;
    let n_tiles = grid.n_tiles;
    let start_line = grid.start_line;
    let min_src_subband = grid.min_src_subband;

    for tile_idx in 0..n_tiles {
        let u = tile_idx as usize;
        let mut strt_cpy = grid.sb_wrap[u];

        // strong whitening detected
        if sub(IGF_WHITENING_STRONG, private.curr_whitening_level[u]) == 0 {
            let mut abs_sum = l_add(0, 0);

            for i in strt_cpy..grid.start_line {
                abs_sum = l_add(abs_sum, l_abs(private.p_spec_flat[i as usize]));
            }

            // fill igf_spec with random noise
            let mut tb = grid.swb_offset[grid.sfb_wrap[u] as usize];

            if abs_sum != 0 {
                for _ in strt_cpy..start_line {
                    igf_spec[tb as usize] = l_deposit_l(random(&mut private.igf_info.nf_seed)); // 31Q0, fill LSBs
                    tb += 1;
                }
            } else {
                for _ in strt_cpy..start_line {
                    igf_spec[tb as usize] = l_add(0, 0);
                    tb += 1;
                }
            }

            // set exponent of the current tile, random noise is 31Q0
            igf_spec_e[u] = 31;
        } else {
            // medium whitening detected
            let mut select_igf_spec = false;
            if sub(IGF_WHITENING_MID, private.curr_whitening_level[u]) == 0 {
                if n_noise_bands != 0 {
                    igf_replace_tcx_noise_2(
                        igf_spec,
                        tcx_noise,
                        min_src_subband,
                        start_line,
                        total_noise_nrg,
                        private.headroom_tcx_noise_white,
                        &mut private.igf_info.nf_seed,
                    );
                }

                // selected source spectrum is igf_spec, igf_spec contains the whitened signal in the core region
                select_igf_spec = true;

                // set exponent of the current tile
                igf_spec_e[u] = spec_med_e;
            } else {
                // off whitening detectded
                if n_noise_bands_off != 0 {
                    igf_replace_tcx_noise_2(
                        &mut private.p_spec_flat,
                        tcx_noise,
                        min_src_subband,
                        start_line,
                        total_noise_nrg_off,
                        private.headroom_tcx_noise,
                        &mut private.igf_info.nf_seed,
                    );
                }
                // selected source spectrum is pSpecFlat, pSpecFlat contains the signal before the LPC reshaping

                // set exponent of the current tile
                igf_spec_e[u] = src_spec_e;
            }
            // generate the raw IGF spectrum out if the selected spectrum
            for sfb in grid.sfb_wrap[u]..grid.sfb_wrap[u + 1] {
                let sfb = sfb as usize;
                for tb in grid.swb_offset[sfb]..grid.swb_offset[sfb + 1] {
                    igf_spec[tb as usize] = if select_igf_spec {
                        igf_spec[strt_cpy as usize]
                    } else {
                        private.p_spec_flat[strt_cpy as usize]
                    };
                    strt_cpy = add(strt_cpy, 1);
                }
            }
        }
    }
}

/// `IGF_calc`: the energies of the survived (core coded) spectrum `sN` and of the prepared IGF
/// spectrum `pN` per SFB, into the private data.
fn igf_calc(
    private: &mut IgfdecPrivateData,
    igf_grid_idx: i16,
    spectrum: &[i32],
    spectrum_e: i16,
    igf_spec: &[i32],
    igf_spec_e: &[i16],
) {
    use crate::evs::com::igf_base::{
        igf_common_funcs_calc_sfb_energy_power_spec, igf_common_funcs_mdct_square_spec,
    };

    let grid = private.igf_info.grid[igf_grid_idx as usize].clone();
    let mut squared_spectra = [0i32; IGF_MAX_GRANULE_LEN as usize]; // Q31 | MDCT^2 spectra
    let mut squared_spectra_e = [0i16; IGF_MAX_TILES as usize]; // exponents of squaredSpectra, one exponent per tile!

    // square the original spectrum
    igf_common_funcs_mdct_square_spec(
        grid.start_line,
        grid.stop_line,
        spectrum,
        spectrum_e,
        &mut squared_spectra,
        &mut squared_spectra_e[0],
        0,
    );

    // calculate the energy per SFB of the survied subbands
    igf_common_funcs_calc_sfb_energy_power_spec(
        grid.start_sfb,
        grid.stop_sfb,
        &grid.swb_offset,
        Some(&squared_spectra),
        &squared_spectra_e[0],
        &mut private.igf_s_n,
        &mut private.igf_s_n_e,
    );

    // loop over tiles, every tile has his own exponent!
    for i in 0..grid.n_tiles as usize {
        // square the prepared IGF spectrum
        igf_common_funcs_mdct_square_spec(
            grid.tile[i],
            grid.tile[i + 1],
            igf_spec,
            igf_spec_e[i],
            &mut squared_spectra,
            &mut squared_spectra_e[i],
            0,
        );

        // set all squared values to 0, if the core contains survied lines
        igf_set_lines_to_zero(
            grid.tile[i],
            grid.tile[i + 1],
            spectrum,
            &mut squared_spectra,
        );

        // calculate the energy per SFB of the processed subbands
        igf_common_funcs_calc_sfb_energy_power_spec(
            grid.sfb_wrap[i],
            grid.sfb_wrap[i + 1],
            &grid.swb_offset,
            Some(&squared_spectra),
            &squared_spectra_e[i],
            &mut private.igf_p_n,
            &mut private.igf_p_n_e,
        );
    }
}

/// `IGF_getWhiteSpectralData`: the spectrum `in_[start..stop]` divided by its moving-average
/// level over `2 * level` lines (the whitening), into `out`. `s_l` is the headroom of `in_`.
fn igf_get_white_spectral_data(
    in_: &[i32],
    s_l: i16,
    out: &mut [i32],
    start: i16,
    stop: i16,
    level: i16,
) {
    const NRG_TAB: [i16; 8] = [
        2341, // 1/14
        2521, // 1/13
        2731, // 1/12
        2979, // 1/11
        3277, // 1/10
        3641, // 1/9
        4096, // 1/8
        4681, // 1/7
    ];
    let mut div: i16;

    // inits
    let s_l = sub(s_l, 2);
    let mut ak = l_add(0, 0); // moving average

    let line = |index: i32| in_[index as usize];
    let (start, stop, level) = (i32::from(start), i32::from(stop), i32::from(level));

    for j in (start - level)..(start + level) {
        let tmp_16 = extract_h(l_shl(line(j), s_l));
        ak = l_mac(ak, tmp_16, tmp_16);
    }
    let mut j = start;
    while j < stop - level {
        let mut tmp_16 = extract_h(l_shl(line(j + level), s_l));
        ak = l_mac(ak, tmp_16, tmp_16);
        let ak_norm = mpy_32_16_r(ak, 2185);
        tmp_16 = sub(31, norm_l(ak_norm));

        if ak == 0 {
            tmp_16 = 0;
        }

        tmp_16 = sub(15, shr(tmp_16, 1)).min(14);
        div = shl(1, tmp_16);
        out[j as usize] = mpy_32_16_1(l_shl(line(j), s_l), div);

        tmp_16 = extract_h(l_shl(line(j - level), s_l));
        ak = l_msu(ak, tmp_16, tmp_16);
        j += 1;
    }

    let mut nrm_i = 0;

    while j < stop {
        let ak_norm = mpy_32_16_r(ak, NRG_TAB[nrm_i]);
        nrm_i += 1;
        let mut tmp_16 = sub(31, norm_l(ak_norm));

        if ak == 0 {
            tmp_16 = 0;
        }

        tmp_16 = sub(15, shr(tmp_16, 1)).min(14);
        div = shl(1, tmp_16);

        if l_sub(ak, 16) < 0 {
            div = 1;
        }

        out[j as usize] = mpy_32_16_1(l_shl(line(j), s_l), div);
        let tmp_16 = extract_h(l_shl(line(j - level), s_l));
        ak = l_msu(ak, tmp_16, tmp_16);
        j += 1;
    }
}

/// `IGF_RefineGrid`: halve the SFB widths of a grid (every band split in two) for the finer
/// envelope of the low IGF bit rates.
fn igf_refine_grid(grid: &mut IgfGrid) {
    let mut a = [0i16; IGF_MAX_SFB as usize + 1];

    grid.info_is_refined = 1;
    for sfb in 0..grid.swb_offset_len as usize {
        let mut tmp = shl(sfb as i16, 1) as usize;
        a[tmp] = grid.swb_offset[sfb];
        tmp += 1;
        let mut delta = sub(grid.swb_offset[sfb + 1], grid.swb_offset[sfb]);
        delta = crate::itu::stl2009::mac_r(0x0019_5000, 29491 /* 0.45f Q16 */, shl(delta, 5));
        a[tmp] = add(grid.swb_offset[sfb], shr(delta, 6));
        if a[tmp] & 1 != 0 {
            a[tmp] = sub(a[tmp], 1);
        }
    }
    grid.stop_sfb = shl(grid.stop_sfb, 1);
    let count = grid.stop_sfb as usize + 1;
    grid.swb_offset[..count].copy_from_slice(&a[..count]);

    for sfb in 0..=grid.n_tiles as usize {
        grid.sfb_wrap[sfb] = shl(grid.sfb_wrap[sfb], 1);
    }
}

/// `IGFDecReadData`: read the whitening levels and the flattening trigger of a frame. An
/// independent frame (`is_indep_frame` 1) carries no "same as before" flag.
pub fn igf_dec_read_data(st: &mut DecoderState, igf_grid_idx: i16, is_indep_frame: i16) {
    let n_t = st.h_igf_dec.igf_data.igf_info.grid[igf_grid_idx as usize].n_tiles;
    let mut tmp: u16 = 0;

    // set/reset all values to default = IGF_WHITENING_OFF
    st.h_igf_dec.igf_data.curr_whitening_level = [IGF_WHITENING_OFF; IGF_MAX_TILES as usize];

    if is_indep_frame == 0 {
        tmp = get_next_indice(st, 1);
    }

    if tmp == 1 {
        for p in 0..n_t as usize {
            st.h_igf_dec.igf_data.curr_whitening_level[p] =
                st.h_igf_dec.igf_data.prev_whitening_level[p];
        }
    } else {
        igf_decode_whitening_level(st, 0);
        tmp = get_next_indice(st, 1);
        if tmp == 1 {
            for p in 1..n_t as usize {
                igf_decode_whitening_level(st, p);
            }
        } else {
            for p in 1..n_t as usize {
                st.h_igf_dec.igf_data.curr_whitening_level[p] =
                    st.h_igf_dec.igf_data.curr_whitening_level[0];
            }
        }
    }

    // save current level for concealment
    st.h_igf_dec.igf_data.prev_whitening_level = st.h_igf_dec.igf_data.curr_whitening_level;

    // read flattening trigger from bitstream
    igf_decode_temp_flattening_trigger(st);
}

/// `IGFDecReadLevel`: read the IGF level information of a frame (the SCFs of the envelope).
/// Sets `infoIGFAllZero`: 1 when no envelope is transmitted.
pub fn igf_dec_read_level(st: &mut DecoderState, igf_grid_idx: i16, is_indep_frame: i16) {
    let (start_sfb, stop_sfb) = {
        let grid = &st.h_igf_dec.igf_data.igf_info.grid[igf_grid_idx as usize];
        (grid.start_sfb as usize, grid.stop_sfb)
    };

    let igf_all_zero = get_next_indice(st, 1) as i16;

    if igf_all_zero == 0 {
        let data = &mut st.h_igf_dec.igf_data;
        let (curr, prev) = (data.igf_curr, &mut data.igf_prev);
        copy(&curr, prev, stop_sfb);

        // 0Q15, hPrivateData->igf_curr = [0, 91]
        // The decoder advances the instance's own arithmetic-decoder state next to the decoder
        // state it lives in, so work on a copy of the instance and put it back.
        let mut scf_decoder = data.h_arith_sc_fdec.clone();
        let mut sfe = [0i16; IGF_MAX_SFB as usize];
        let sfe_len = IGF_MAX_SFB as usize - start_sfb;
        sfe[..sfe_len].copy_from_slice(&data.igf_curr[start_sfb..]);
        igf_scf_decoder_decode(&mut scf_decoder, st, &mut sfe[..sfe_len], is_indep_frame);
        let data = &mut st.h_igf_dec.igf_data;
        data.igf_curr[start_sfb..].copy_from_slice(&sfe[..sfe_len]);
        data.h_arith_sc_fdec = scf_decoder;
    } else {
        let data = &mut st.h_igf_dec.igf_data;
        igf_scf_decoder_reset(&mut data.h_arith_sc_fdec);
        set16(
            &mut data.igf_curr[start_sfb..],
            0,
            sub(stop_sfb, start_sfb as i16),
        );
    }

    st.h_igf_dec.info_igf_all_zero = igf_all_zero;
}

/// `IGFDecApplyMono`: apply the IGF decoder to the MDCT `spectrum` (exponent `spectrum_e`).
/// `bfi` is 1 for a lost frame.
pub fn igf_dec_apply_mono(
    h_instance: &mut IgfdecInstance,
    spectrum: &mut [i32],
    spectrum_e: &mut i16,
    igf_grid_idx: i16,
    bfi: i16,
) {
    let IgfdecInstance {
        info_igf_all_zero,
        info_tcx_noise,
        virtual_spec,
        virtual_spec_e,
        flag_sparse,
        igf_data: private,
        ..
    } = h_instance;
    let grid = private.igf_info.grid[igf_grid_idx as usize].clone();
    let mut igf_spec = [0i32; IGF_MAX_GRANULE_LEN as usize]; // Q31 | prepared IGF spectrum
    let mut igf_spec_e = [0i16; IGF_MAX_TILES as usize]; // exponents of igf_spec, one exponent per tile

    // initialize variables
    let white_level: i16 = 7;
    let mut spec_med_e: i16 = 0;
    private.n_noise_bands = 0;
    private.n_noise_bands_off = 0;
    private.headroom_tcx_noise_white = 0;
    private.headroom_tcx_noise = 0;
    private.total_noise_nrg = l_add(0, 0);
    private.total_noise_nrg_off = l_add(0, 0);

    set32(&mut igf_spec, 0, IGF_MAX_GRANULE_LEN);
    set16(&mut igf_spec_e, 0, IGF_MAX_TILES);

    // concealment counter
    if bfi != 0 {
        private.frame_loss_counter = add(private.frame_loss_counter, 1);
    } else {
        private.frame_loss_counter = 0;
    }

    // skip IGF processing if all IGF levels are zero
    if *info_igf_all_zero == 0 {
        for i in 0..grid.n_tiles as usize {
            if sub(private.curr_whitening_level[i], IGF_WHITENING_MID) == 0 {
                let s_l = get_scale_factor32(
                    &private.p_spec_flat[(grid.min_src_subband - white_level) as usize..],
                    add(sub(grid.start_line, grid.min_src_subband), white_level),
                );

                spec_med_e = private.p_spec_flat_exp;
                igf_get_white_spectral_data(
                    &private.p_spec_flat,
                    s_l,
                    &mut igf_spec,
                    grid.min_src_subband,
                    grid.start_line,
                    white_level,
                );

                // 14 seems to be precise enough
                let min_src = grid.min_src_subband as usize;
                private.headroom_tcx_noise_white = igf_get_scale_factor32_cond(
                    &info_tcx_noise[min_src..],
                    &igf_spec[min_src..],
                    sub(grid.start_line, grid.min_src_subband),
                );
                private.n_noise_bands = igf_replace_tcx_noise_1(
                    &igf_spec,
                    private.headroom_tcx_noise_white,
                    info_tcx_noise,
                    grid.min_src_subband,
                    grid.start_line,
                    &mut private.total_noise_nrg,
                );

                break;
            }
        }

        for i in 0..grid.n_tiles as usize {
            if private.curr_whitening_level[i] == IGF_WHITENING_OFF {
                let min_src = grid.min_src_subband as usize;
                private.headroom_tcx_noise = igf_get_scale_factor32_cond(
                    &info_tcx_noise[min_src..],
                    &private.p_spec_flat[min_src..],
                    sub(grid.start_line, grid.min_src_subband),
                );

                private.n_noise_bands_off = igf_replace_tcx_noise_1(
                    &private.p_spec_flat,
                    private.headroom_tcx_noise,
                    info_tcx_noise,
                    grid.min_src_subband,
                    grid.start_line,
                    &mut private.total_noise_nrg_off,
                );
                break;
            }
        }

        // apply IGF in three steps:
        let src_spec_e = private.p_spec_flat_exp;
        igf_prep(
            private,
            igf_grid_idx,
            info_tcx_noise,
            &mut igf_spec,
            &mut igf_spec_e,
            src_spec_e,
            spec_med_e,
        );
        igf_calc(
            private,
            igf_grid_idx,
            spectrum,
            *spectrum_e,
            &igf_spec,
            &igf_spec_e,
        );
        appl::igf_appl(
            private,
            igf_grid_idx,
            appl::ApplyIo {
                spectrum,
                spectrum_e,
                igf_spec: &igf_spec,
                igf_spec_e: &igf_spec_e,
                virtual_spec,
                virtual_spec_e,
                flag_sparse,
                info_tcx_noise,
            },
        );
    }

    // reset TCX noise indicator vector
    set16(info_tcx_noise, 0, IGF_START_MX);
}

/// `IGFDecSetMode`: initialise the IGF decoder for a bit rate and bandwidth `mode` (which is the
/// bandwidth constant). `default_start_line` / `default_stop_line` are what the instance reports
/// when the bit rate has no IGF configuration.
pub fn igf_dec_set_mode(
    h_instance: &mut IgfdecInstance,
    bit_rate: i32,
    mode: i16,
    default_start_line: i16,
    default_stop_line: i16,
    rf_mode: i16,
) {
    h_instance.is_igf_active = 0;

    if igf_common_funcs_igf_configuration(
        bit_rate,
        mode,
        &mut h_instance.igf_data.igf_info,
        rf_mode,
    ) != 0
    {
        let grid0 = &h_instance.igf_data.igf_info.grid[0];
        let scf_count_long_block = sub(grid0.stop_sfb, grid0.start_sfb);
        igf_scf_decoder_open(
            &mut h_instance.igf_data.h_arith_sc_fdec,
            scf_count_long_block,
            bit_rate,
            mode,
            rf_mode,
        );

        let grid0 = &h_instance.igf_data.igf_info.grid[0];
        h_instance.info_igf_stop_line = grid0.stop_line;
        h_instance.info_igf_start_line = grid0.start_line;
        h_instance.info_igf_stop_freq = grid0.stop_frequency;
        h_instance.info_igf_start_freq = grid0.start_frequency;
        h_instance.info_igf_all_zero = 0;
        h_instance.is_igf_active = 1;

        let bit_rate_index = h_instance.igf_data.igf_info.bit_rate_index;
        if sub(bit_rate_index, IGF_BITRATE_SWB_48000) <= 0
            || sub(bit_rate_index, IGF_BITRATE_FB_48000) <= 0
        {
            igf_refine_grid(&mut h_instance.igf_data.igf_info.grid[IGF_GRID_LB_NORM as usize]);
            igf_refine_grid(&mut h_instance.igf_data.igf_info.grid[IGF_GRID_LB_TRAN as usize]);
            igf_refine_grid(&mut h_instance.igf_data.igf_info.grid[IGF_GRID_LB_SHORT as usize]);
        }
    } else {
        h_instance.info_igf_stop_line = default_stop_line;
        h_instance.info_igf_start_line = default_start_line;
        h_instance.info_igf_stop_freq = -1;
        h_instance.info_igf_start_freq = -1;
        // The reference prints "IGFDecSetMode: initialization error!" to stderr here; nothing
        // downstream reads it.
    }
}

/// `IGFDecUpdateInfo`: report the start / stop line and frequency of the grid `igf_grid_idx`.
pub fn igf_dec_update_info(h_instance: &mut IgfdecInstance, igf_grid_idx: i16) {
    if h_instance.is_igf_active != 0 {
        let grid = &h_instance.igf_data.igf_info.grid[igf_grid_idx as usize];
        h_instance.info_igf_start_freq = grid.start_frequency;
        h_instance.info_igf_stop_freq = grid.stop_frequency;
        h_instance.info_igf_start_line = grid.start_line;
        h_instance.info_igf_stop_line = grid.stop_line;
    }
}

/// `IGFDecCopyLPCFlatSpectrum`: keep the LPC-flattened TCX spectrum `p_spectrum_flat` (exponent
/// `p_spectrum_flat_exp`) up to the IGF start line as the IGF source spectrum.
pub fn igf_dec_copy_lpc_flat_spectrum(
    h_instance: &mut IgfdecInstance,
    p_spectrum_flat: &[i32],
    p_spectrum_flat_exp: i16,
    igf_grid_idx: i16,
) {
    let private = &mut h_instance.igf_data;
    let start_line = private.igf_info.grid[igf_grid_idx as usize].start_line;

    // pSpectrumFlat_exp has to be multiplied with 1024 = 2^10 go achive proper gain values
    private.p_spec_flat_exp = add(p_spectrum_flat_exp, 10);

    copy32(p_spectrum_flat, &mut private.p_spec_flat, start_line);
}

/// `IGFDecStoreTCX10SubFrameData`: keep the IGF bitstream information of the TCX10 subframe
/// `sub_frame_idx`.
pub fn igf_dec_store_tcx10_sub_frame_data(h_instance: &mut IgfdecInstance, sub_frame_idx: i16) {
    let index = sub_frame_idx as usize;
    let flattening_trigger = h_instance.flattening_trigger;
    let private = &mut h_instance.igf_data;

    // store igf energies for subframe
    private.igf_curr_subframe[index][0] = private.igf_curr;
    private.igf_prev_subframe[index] = private.igf_prev;

    // store spectral whitening information for current subframe
    private.curr_whitening_level_subframe[index] = private.curr_whitening_level;
    private.prev_whitening_level_subframe[index] = private.prev_whitening_level;
    // store flattening trigger for current subframe
    private.igf_flattening_trigger_subframe[index] = flattening_trigger;
}

/// `IGFDecRestoreTCX10SubFrameData`: restore the IGF bitstream information of the TCX10 subframe
/// `sub_frame_idx` stored by [`igf_dec_store_tcx10_sub_frame_data`].
pub fn igf_dec_restore_tcx10_sub_frame_data(h_instance: &mut IgfdecInstance, sub_frame_idx: i16) {
    let index = sub_frame_idx as usize;
    let private = &mut h_instance.igf_data;

    // restore igf energies for subframe
    private.igf_curr = private.igf_curr_subframe[index][0];
    private.igf_prev = private.igf_prev_subframe[index];

    // restore spectral whitening information for current subframe
    private.curr_whitening_level = private.curr_whitening_level_subframe[index];
    private.prev_whitening_level = private.prev_whitening_level_subframe[index];
    // restore flattening trigger for current subframe
    h_instance.flattening_trigger = private.igf_flattening_trigger_subframe[index];
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::cnst::IGF_MODE_SWB;

    #[test]
    fn scale_factor_of_the_masked_lines_ignores_the_others() {
        let cond = [1, 0, 1];
        let x = [0x0000_0100, 0x4000_0000, -0x0000_0100];
        // only |0x100| counts: norm_l(0x100) = 22, norm_l(-0x100) = 23
        assert_eq!(igf_get_scale_factor32_cond(&cond, &x, 3), 22);
        assert_eq!(igf_get_scale_factor32_cond(&[0, 0, 0], &x, 3), 0x20 & 0x1F);
    }

    #[test]
    fn tcx_noise_measure_counts_the_flagged_lines() {
        let spectrum = [0x0100_0000, 0x0200_0000, 0x0300_0000];
        let noise = [1, 0, 1];
        let mut energy = 0;
        let count = igf_replace_tcx_noise_1(&spectrum, 5, &noise, 0, 3, &mut energy);
        assert_eq!(count, 2);
        assert!(energy > 0);
    }

    #[test]
    fn set_mode_refines_the_low_rate_grids_and_activates_igf() {
        let mut instance = IgfdecInstance::zeroed();
        igf_dec_set_mode(&mut instance, 9600, IGF_MODE_SWB, -1, -1, 0);
        assert_eq!(instance.is_igf_active, 1);
        assert_eq!(instance.info_igf_all_zero, 0);
        assert_eq!(instance.igf_data.igf_info.grid[0].info_is_refined, 1);
        // the SCF count is taken before the grid is refined (its band count doubles)
        let grid = &instance.igf_data.igf_info.grid[0];
        assert_eq!(
            instance.igf_data.h_arith_sc_fdec.scf_count_long_block,
            sub(grid.stop_sfb / 2, grid.start_sfb)
        );
        // a rate without IGF keeps the defaults and the instance inactive
        igf_dec_set_mode(&mut instance, 13200, 1, 5, 7, 0);
        assert_eq!(instance.is_igf_active, 0);
        assert_eq!(instance.info_igf_start_line, 5);
        assert_eq!(instance.info_igf_stop_freq, -1);
    }

    #[test]
    fn update_info_follows_the_grid_only_while_active() {
        let mut instance = IgfdecInstance::zeroed();
        igf_dec_update_info(&mut instance, 1);
        assert_eq!(instance.info_igf_start_line, 0);
        igf_dec_set_mode(&mut instance, 24400, IGF_MODE_SWB, -1, -1, 0);
        igf_dec_update_info(&mut instance, IGF_GRID_LB_TRAN);
        assert_eq!(
            instance.info_igf_start_line,
            instance.igf_data.igf_info.grid[1].start_line
        );
    }

    #[test]
    fn tcx10_subframe_data_round_trips() {
        let mut instance = IgfdecInstance::zeroed();
        instance.igf_data.igf_curr[3] = 42;
        instance.igf_data.curr_whitening_level[1] = IGF_WHITENING_MID;
        instance.flattening_trigger = 1;
        igf_dec_store_tcx10_sub_frame_data(&mut instance, 1);
        instance.igf_data.igf_curr[3] = 0;
        instance.igf_data.curr_whitening_level[1] = 0;
        instance.flattening_trigger = 0;
        igf_dec_restore_tcx10_sub_frame_data(&mut instance, 1);
        assert_eq!(instance.igf_data.igf_curr[3], 42);
        assert_eq!(instance.igf_data.curr_whitening_level[1], IGF_WHITENING_MID);
        assert_eq!(instance.flattening_trigger, 1);
    }

    #[test]
    fn lpc_flat_spectrum_is_copied_up_to_the_start_line() {
        let mut instance = IgfdecInstance::zeroed();
        igf_dec_set_mode(&mut instance, 24400, IGF_MODE_SWB, -1, -1, 0);
        let source = [7i32; 800];
        igf_dec_copy_lpc_flat_spectrum(&mut instance, &source, 3, 0);
        let start_line = instance.igf_data.igf_info.grid[0].start_line as usize;
        assert_eq!(instance.igf_data.p_spec_flat_exp, 13);
        assert_eq!(instance.igf_data.p_spec_flat[start_line - 1], 7);
        assert_eq!(instance.igf_data.p_spec_flat[start_line], 0);
    }
}
