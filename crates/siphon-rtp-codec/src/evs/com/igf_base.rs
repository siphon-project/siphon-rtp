//! Intelligent Gap Filling, parts shared by the encoder and decoder (TS 26.442
//! `lib_com/igf_base.c`; TS 26.445 clause 5.3.3.2.11 for the tool).
//!
//! Ported: the bit-rate to configuration index map, the grid set-up, `IGFCommonFuncsIGFConfiguration`,
//! the cumulative-frequency table selection of the SCF arithmetic coder, and the two spectrum
//! helpers (square spectrum, energy per scale-factor band). `IGFCommonFuncsWriteSerialBit` is the
//! encoder's bit writer (it calls `push_next_indice_fx` on an encoder state) and no decoder path
//! reaches it, so it is not part of this port.

use crate::evs::cnst::{
    IGF_BITRATE_FB_128000, IGF_BITRATE_FB_16400, IGF_BITRATE_FB_24400, IGF_BITRATE_FB_32000,
    IGF_BITRATE_FB_48000, IGF_BITRATE_FB_96000, IGF_BITRATE_RF_SWB_13200, IGF_BITRATE_RF_WB_13200,
    IGF_BITRATE_SWB_13200, IGF_BITRATE_SWB_16400, IGF_BITRATE_SWB_24400, IGF_BITRATE_SWB_32000,
    IGF_BITRATE_SWB_48000, IGF_BITRATE_SWB_9600, IGF_BITRATE_UNKNOWN, IGF_BITRATE_WB_9600,
    IGF_GRID_LB_NORM, IGF_GRID_LB_SHORT, IGF_GRID_LB_TRAN, IGF_MAX_TILES, IGF_MODE_FB,
    IGF_MODE_SWB, IGF_MODE_WB, WORD16_BITS,
};
use crate::evs::com::basop_util::{get_scale_factor32, imult1616, norm_ll_q31};
use crate::evs::dec::state::{IgfGrid, IgfInfo};
use crate::evs::rom::{
    CF_OFF_SE01_TAB, CF_OFF_SE02_TAB, CF_OFF_SE10_TAB, CF_OFF_SE11_TAB, CF_SE00_TAB, CF_SE01_TAB,
    CF_SE02_TAB, CF_SE10_TAB, CF_SE11_TAB, IGFMODE, IGF_WHITENING_TH, SWB_OFFSET_LB_NEW,
};
use crate::itu::basic_ops::{
    add, div_s, extract_h, extract_l, l_deposit_l, l_shl, l_shr, norm_l, norm_s, round_word, shl,
    shr, sub,
};
use crate::itu::stl2009::{l_add_c, l_mac_ns, l_mult0, StlFlags};

/// `IGF_ApplyTransFac`: `val` scaled by the transition factor `trans_fac` (Q14), rounded to an
/// even integer. A factor of 1.0 returns `val` unchanged.
#[must_use]
pub fn igf_apply_trans_fac(val: i16, trans_fac: i16) -> i16 {
    if sub(trans_fac, 0x4000) == 0 {
        return val;
    }

    let mut ret = shl(val, 1);
    ret = crate::itu::stl2009::mac_r(0x0000_0000, ret, trans_fac);
    ret = add(ret, ret & 1);

    ret
}

/// `IGF_MapBitRateToIndex`: the IGF bit-rate index of a bit rate and bandwidth mode, or
/// `IGF_BITRATE_UNKNOWN`.
///
/// The reference `assert(0)`s on a bit rate its table does not list; with asserts off (the build
/// that produced the conformance sequences) that leaves the initial `IGF_BITRATE_UNKNOWN`, which
/// is what this returns.
#[must_use]
pub fn igf_map_bit_rate_to_index(bit_rate: i32, mode: i16, rf_mode: i16) -> i16 {
    let mut bit_rate_index = IGF_BITRATE_UNKNOWN;

    match mode {
        IGF_MODE_WB => match bit_rate {
            13200 => {
                if sub(rf_mode, 1) == 0 {
                    bit_rate_index = IGF_BITRATE_RF_WB_13200;
                }
            }
            9600 => bit_rate_index = IGF_BITRATE_WB_9600,
            _ => {}
        },
        IGF_MODE_SWB => match bit_rate {
            9600 => bit_rate_index = IGF_BITRATE_SWB_9600,
            13200 => {
                bit_rate_index = IGF_BITRATE_SWB_13200;
                if sub(rf_mode, 1) == 0 {
                    bit_rate_index = IGF_BITRATE_RF_SWB_13200;
                }
            }
            16400 => bit_rate_index = IGF_BITRATE_SWB_16400,
            24400 => bit_rate_index = IGF_BITRATE_SWB_24400,
            32000 => bit_rate_index = IGF_BITRATE_SWB_32000,
            48000 => bit_rate_index = IGF_BITRATE_SWB_48000,
            _ => {}
        },
        IGF_MODE_FB => match bit_rate {
            16400 => bit_rate_index = IGF_BITRATE_FB_16400,
            24400 => bit_rate_index = IGF_BITRATE_FB_24400,
            32000 => bit_rate_index = IGF_BITRATE_FB_32000,
            48000 => bit_rate_index = IGF_BITRATE_FB_48000,
            96000 => bit_rate_index = IGF_BITRATE_FB_96000,
            128000 => bit_rate_index = IGF_BITRATE_FB_128000,
            _ => {}
        },
        _ => {}
    }

    bit_rate_index
}

/// The tile layout `IGF_gridSetUp` picks for a bit-rate index: the wrap SFBs (`sfbWrap[1..]`
/// before the last, which is always `stopSfb`), the source-subband offsets and the tile count.
fn igf_grid_set_up_tiles(grid: &mut IgfGrid, bit_rate_index: i16, trans_fac: i16) -> bool {
    let apply = |value: i16| igf_apply_trans_fac(value, trans_fac);
    let stop_sfb = grid.stop_sfb as usize;
    let min_src = grid.min_src_subband;

    match bit_rate_index {
        IGF_BITRATE_WB_9600 | IGF_BITRATE_RF_WB_13200 => {
            grid.n_tiles = 2;
            let wrp_sfb: i16 = 2;

            // 1st
            grid.sfb_wrap[1] = wrp_sfb;
            grid.sb_wrap[0] = min_src;
            grid.tile[1] = grid.swb_offset[wrp_sfb as usize];

            // 2nd
            grid.sfb_wrap[2] = grid.stop_sfb;
            grid.sb_wrap[1] = min_src;
            grid.tile[2] = grid.swb_offset[stop_sfb];
        }
        IGF_BITRATE_SWB_9600 | IGF_BITRATE_RF_SWB_13200 => {
            grid.n_tiles = 3;
            let mut wrp_sfb: i16 = 1;

            // 1st
            grid.sfb_wrap[1] = wrp_sfb;
            grid.sb_wrap[0] = min_src;
            grid.tile[1] = grid.swb_offset[wrp_sfb as usize];

            // 2nd
            wrp_sfb = 2;
            grid.sfb_wrap[2] = wrp_sfb;
            grid.sb_wrap[1] = min_src.wrapping_add(apply(32));
            grid.tile[2] = grid.swb_offset[wrp_sfb as usize];

            // 3rd
            grid.sfb_wrap[3] = grid.stop_sfb;
            grid.sb_wrap[2] = min_src.wrapping_add(apply(46));
            grid.tile[3] = grid.swb_offset[stop_sfb];
        }
        IGF_BITRATE_SWB_13200 => {
            grid.n_tiles = 2;
            let wrp_sfb: i16 = 4;

            // 1st
            grid.sfb_wrap[1] = wrp_sfb;
            grid.sb_wrap[0] = min_src;
            grid.tile[1] = grid.swb_offset[wrp_sfb as usize];

            // 2nd
            grid.sfb_wrap[2] = grid.stop_sfb;
            grid.sb_wrap[1] = add(min_src, apply(32));
            grid.tile[2] = grid.swb_offset[stop_sfb];
        }
        IGF_BITRATE_SWB_16400 => {
            grid.n_tiles = 3;
            let wrp_sfb: i16 = 4;

            // 1st
            grid.sfb_wrap[1] = wrp_sfb;
            grid.sb_wrap[0] = min_src;
            grid.tile[1] = grid.swb_offset[wrp_sfb as usize];

            // 2nd
            grid.sfb_wrap[2] = 6;
            grid.sb_wrap[1] = add(min_src, apply(48));
            grid.tile[2] = grid.swb_offset[6];

            // 3rd
            grid.sfb_wrap[3] = grid.stop_sfb;
            grid.sb_wrap[2] = add(min_src, apply(64));
            grid.tile[3] = grid.swb_offset[stop_sfb];
        }
        IGF_BITRATE_SWB_24400 | IGF_BITRATE_SWB_32000 => {
            grid.n_tiles = 3;
            let wrp_sfb: i16 = 4;

            // 1st
            grid.sfb_wrap[1] = wrp_sfb;
            grid.sb_wrap[0] = min_src;
            grid.tile[1] = grid.swb_offset[wrp_sfb as usize];

            // 2nd
            grid.sfb_wrap[2] = 7;
            grid.sb_wrap[1] = add(min_src, apply(32));
            grid.tile[2] = grid.swb_offset[7];

            // 3rd
            grid.sfb_wrap[3] = grid.stop_sfb;
            grid.sb_wrap[2] = add(min_src, apply(64));
            grid.tile[3] = grid.swb_offset[stop_sfb];
        }
        IGF_BITRATE_SWB_48000 => {
            grid.n_tiles = 1;

            // 1st
            grid.sfb_wrap[1] = grid.stop_sfb;
            grid.sb_wrap[0] = sub(shl(grid.start_line, 1), grid.stop_line);
            grid.tile[1] = grid.swb_offset[stop_sfb];
        }
        IGF_BITRATE_FB_16400 => {
            grid.n_tiles = 3;
            let mut wrp_sfb: i16 = 4;

            // 1st
            grid.sfb_wrap[1] = wrp_sfb;
            grid.sb_wrap[0] = min_src;
            grid.tile[1] = grid.swb_offset[wrp_sfb as usize];
            wrp_sfb = 7;

            // 2nd
            grid.sfb_wrap[2] = wrp_sfb;
            grid.sb_wrap[1] = min_src;
            grid.tile[2] = grid.swb_offset[wrp_sfb as usize];

            // 3rd
            grid.sfb_wrap[3] = grid.stop_sfb;
            grid.sb_wrap[2] = min_src;
            grid.tile[3] = grid.swb_offset[stop_sfb];
        }
        IGF_BITRATE_FB_24400 | IGF_BITRATE_FB_32000 => {
            grid.n_tiles = 4;
            let mut wrp_sfb: i16 = 4;

            // 1st
            grid.sfb_wrap[1] = wrp_sfb;
            grid.sb_wrap[0] = min_src;
            grid.tile[1] = grid.swb_offset[wrp_sfb as usize];
            wrp_sfb = 6;

            // 2nd
            grid.sfb_wrap[2] = wrp_sfb;
            grid.sb_wrap[1] = add(min_src, apply(32));
            grid.tile[2] = grid.swb_offset[wrp_sfb as usize];
            wrp_sfb = 9;

            // 3rd
            grid.sfb_wrap[3] = wrp_sfb;
            grid.sb_wrap[2] = min_src;
            grid.tile[3] = grid.swb_offset[wrp_sfb as usize];

            // 4th
            grid.sfb_wrap[4] = grid.stop_sfb;
            grid.sb_wrap[3] = add(min_src, sub(grid.swb_offset[9], grid.swb_offset[8]));
            grid.tile[4] = grid.swb_offset[stop_sfb];
        }
        IGF_BITRATE_FB_48000 | IGF_BITRATE_FB_96000 | IGF_BITRATE_FB_128000 => {
            grid.n_tiles = 1;

            // 1st
            grid.sfb_wrap[1] = grid.stop_sfb;
            grid.sb_wrap[0] = sub(shl(grid.start_line, 1), grid.stop_line);
            grid.tile[1] = grid.swb_offset[stop_sfb];
        }
        _ => return false,
    }
    true
}

/// The level-envelope adaption factors `IGF_gridSetUp` selects (`gFactor`, `fFactor`, `lFactor`,
/// all Q14).
fn igf_grid_set_up_level_factors(grid: &mut IgfGrid, bit_rate_index: i16) {
    // adapt level envelope:
    match bit_rate_index {
        IGF_BITRATE_RF_WB_13200 | IGF_BITRATE_WB_9600 => {
            grid.g_factor = 13107; // 0.80f Q14
            grid.f_factor = 11469; // 0.70f Q14
            grid.l_factor = 9830; // 0.60f Q14
        }
        IGF_BITRATE_SWB_13200 | IGF_BITRATE_FB_16400 | IGF_BITRATE_SWB_16400 => {
            grid.g_factor = 15237; // 0.93f Q14
            grid.f_factor = 3277; // 0.20f Q14
            grid.l_factor = 13926; // 0.85f Q14
        }
        IGF_BITRATE_FB_24400
        | IGF_BITRATE_SWB_24400
        | IGF_BITRATE_FB_32000
        | IGF_BITRATE_SWB_32000 => {
            grid.g_factor = 15811; // 0.965f Q14
            grid.f_factor = 3277; // 0.20f Q14
            grid.l_factor = 13926; // 0.85f Q14
        }
        IGF_BITRATE_FB_48000 | IGF_BITRATE_SWB_48000 => {
            grid.g_factor = 16384; // 1.00f Q14
            grid.f_factor = 3277; // 0.20f Q14
            grid.l_factor = 16384; // 1.00f Q14
        }
        // IGF_BITRATE_SWB_9600, IGF_BITRATE_RF_SWB_13200 and the rest
        _ => {
            grid.g_factor = 16384; // 1.00f Q14
            grid.f_factor = 0; // 0.00f Q14
            grid.l_factor = 16384; // 1.00f Q14
        }
    }
}

/// `IGF_gridSetUp`: set up one IGF grid (the SFB layout, the tiles, the source regions and the
/// envelope adaption factors) for a bit-rate index, sampling rate, frame length and transition
/// factor `trans_fac` (Q14).
///
/// The reference `assert(0)`s on `IGF_BITRATE_UNKNOWN` and then reads through a NULL table; its only
/// caller never passes that index, and here it leaves the grid untouched.
pub fn igf_grid_set_up(
    grid: &mut IgfGrid,
    bit_rate_index: i16,
    sample_rate: i32,
    frame_length: i16,
    trans_fac: i16,
    igf_min_fq: i16,
) {
    let (swb_offset, swb_offset_len): (&[i16], i16) = match bit_rate_index {
        0..=14 => {
            let row = &SWB_OFFSET_LB_NEW[bit_rate_index as usize];
            let whitening = &IGF_WHITENING_TH[bit_rate_index as usize];
            // Copy(&igf_whitening_TH[bitRateIndex][0][0], &hGrid->whiteningThreshold[0][0],
            //      IGF_MAX_TILES * 2)
            for (destination, source) in grid.whitening_threshold.iter_mut().zip(whitening.iter()) {
                *destination = *source;
            }
            (&row[1..], row[0])
        }
        _ => return,
    };

    for sfb in 0..swb_offset_len as usize {
        grid.swb_offset[sfb] = igf_apply_trans_fac(swb_offset[sfb], trans_fac);
    }

    grid.info_is_refined = 0;
    let frame_length = igf_apply_trans_fac(frame_length, trans_fac);
    let mut tmp2 = norm_s(frame_length);
    let mut bandwidth = shl(frame_length, tmp2);
    grid.swb_offset_len = extract_l(l_shr(sample_rate, 2));
    let mut tmp1 = sub(norm_s(grid.swb_offset_len), 1);
    grid.swb_offset_len = shl(grid.swb_offset_len, tmp1);
    bandwidth = div_s(grid.swb_offset_len, bandwidth);
    tmp2 = sub(add(tmp2, 1), tmp1);
    bandwidth = shr(bandwidth, sub(15, tmp2));

    grid.swb_offset_len = swb_offset_len;
    grid.start_sfb = 0;
    grid.stop_sfb = sub(grid.swb_offset_len, 1);
    grid.start_line = grid.swb_offset[grid.start_sfb as usize];
    grid.stop_line = grid.swb_offset[grid.stop_sfb as usize];
    grid.start_frequency = imult1616(bandwidth, grid.start_line);
    grid.stop_frequency = imult1616(bandwidth, grid.stop_line);

    let mut l_tmp1 = l_mult0(igf_min_fq, frame_length);
    tmp1 = sub(norm_l(l_tmp1), 1);
    l_tmp1 = l_shl(l_tmp1, tmp1);

    tmp2 = norm_l(sample_rate);
    let l_tmp2 = l_shl(sample_rate, tmp2);
    // takes into account sampleRate >> 1
    tmp1 = add(WORD16_BITS - 1, sub(tmp1, add(tmp2, 1)));

    grid.min_src_subband = div_s(extract_h(l_tmp1), extract_h(l_tmp2));
    grid.min_src_subband = shr(grid.min_src_subband, tmp1);

    grid.min_src_subband = add(grid.min_src_subband, grid.min_src_subband & 1);
    grid.min_src_frequency = imult1616(bandwidth, grid.min_src_subband);
    grid.info_granule_len = frame_length;
    grid.info_trans_fac = trans_fac;

    grid.sfb_wrap[0] = 0;
    grid.tile[0] = grid.start_line;

    if !igf_grid_set_up_tiles(grid, bit_rate_index, trans_fac) {
        return;
    }

    igf_grid_set_up_level_factors(grid, bit_rate_index);

    for t in add(grid.n_tiles, 1)..IGF_MAX_TILES {
        grid.tile[t as usize] = 0;
        grid.sb_wrap[(t - 1) as usize] = 0;
        grid.sfb_wrap[t as usize] = 0;
    }
}

/// `IGFCommonFuncsCalcSfbEnergyPowerSpec`: the energy of each scale-factor band in
/// `start_sfb..stop_sfb` as a 64-bit sum of the power spectrum lines, normalised to a Q31
/// mantissa in `sfb_energy[sfb]` with its exponent (offset by `*power_spectrum_exp`) in
/// `sfb_energy_exp[sfb]`. With no power spectrum (the reference's NULL) the energies are zero and
/// the exponents are left alone.
pub fn igf_common_funcs_calc_sfb_energy_power_spec(
    start_sfb: i16,
    stop_sfb: i16,
    swb_offset: &[i16],
    power_spectrum: Option<&[i32]>,
    power_spectrum_exp: &i16,
    sfb_energy: &mut [i32],
    sfb_energy_exp: &mut [i16],
) {
    let mut flags = StlFlags::default();

    for sfb in start_sfb..stop_sfb {
        sfb_energy[sfb as usize] = l_deposit_l(0);
    }
    let Some(power_spectrum) = power_spectrum else {
        return;
    };

    for sfb in start_sfb..stop_sfb {
        let sfb = sfb as usize;
        let mut l_c = l_deposit_l(0);
        for line in swb_offset[sfb]..swb_offset[sfb + 1] {
            flags.carry = false; // Carry = 0
            sfb_energy[sfb] = l_add_c(sfb_energy[sfb], power_spectrum[line as usize], &mut flags);
            flags.overflow = false; // Overflow = 0
            l_c = l_mac_ns(l_c, 0, 0, &mut flags);
        }
        sfb_energy[sfb] = norm_ll_q31(l_c, sfb_energy[sfb], &mut sfb_energy_exp[sfb], &mut flags);
        sfb_energy_exp[sfb] = add(sfb_energy_exp[sfb], *power_spectrum_exp);
    }
}

/// `IGFCommonFuncsMDCTSquareSpec`: the squared MDCT lines `sqrt_bgn..sqrt_end` (each reduced to
/// 16 bits after the common headroom is applied) stored from `mdct_square_spec[sqrt_bgn +
/// index_offset]`; `*mdct_square_spec_e` is their exponent.
pub fn igf_common_funcs_mdct_square_spec(
    sqrt_bgn: i16,
    sqrt_end: i16,
    mdct_spec: &[i32],
    mdct_spec_e: i16,
    mdct_square_spec: &mut [i32],
    mdct_square_spec_e: &mut i16,
    index_offset: i16,
) {
    // get headroom, only in IGF range
    let s1 = get_scale_factor32(&mdct_spec[sqrt_bgn as usize..], sub(sqrt_end, sqrt_bgn));

    // set new exponent
    *mdct_square_spec_e = add(shl(sub(mdct_spec_e, s1), 1), 1);

    // MDCT square spectrum: MDCT^2
    let mut j = add(sqrt_bgn, index_offset); // handle indexOffset with care, otherwise memory overruns may occur!

    for i in sqrt_bgn..sqrt_end {
        let tmp = round_word(l_shl(mdct_spec[i as usize], s1));
        mdct_square_spec[j as usize] = l_mult0(tmp, tmp);
        j = j.wrapping_add(1);
    }
}

/// `IGFCommonFuncsIGFConfiguration`: set the IGF info (the three grids for TCX20, the CELP to TCX
/// transition and TCX10) for a bit rate and bandwidth mode. Returns 1, or 0 when the bit rate has
/// no IGF configuration (nothing is written then except `bitRateIndex`).
pub fn igf_common_funcs_igf_configuration(
    bit_rate: i32,
    mode: i16,
    igf_info: &mut IgfInfo,
    rf_mode: i16,
) -> i16 {
    let mut ret_value = 0; // bitrate index is unknown -> error!

    // interface call for reading in settings
    igf_info.bit_rate_index = igf_map_bit_rate_to_index(bit_rate, mode, rf_mode);

    if sub(igf_info.bit_rate_index, IGF_BITRATE_UNKNOWN) != 0 {
        ret_value = 1; // no error

        // mapping to local values
        let igf_mode = &IGFMODE[igf_info.bit_rate_index as usize];
        let sample_rate = igf_mode.sample_rate;
        let frame_length = igf_mode.frame_length;
        let igf_min_fq = igf_mode.igf_min_fq;
        let max_hopsize = igf_mode.max_hopsize;

        // basic information
        igf_info.sample_rate = sample_rate;
        igf_info.frame_length = frame_length;
        igf_info.max_hopsize = max_hopsize;
        igf_info.nf_seed = 0;

        let bit_rate_index = igf_info.bit_rate_index;

        // set up regular IGF grid for TCX 20 (transfac = 1.f)
        igf_grid_set_up(
            &mut igf_info.grid[IGF_GRID_LB_NORM as usize],
            bit_rate_index,
            sample_rate,
            frame_length,
            16384, // 1 Q14
            igf_min_fq,
        );

        // set up IGF grid for CELP->TCX 20 transitions (transfac = 1.25)
        igf_grid_set_up(
            &mut igf_info.grid[IGF_GRID_LB_TRAN as usize],
            bit_rate_index,
            sample_rate,
            frame_length,
            20480, // 1.25 Q14
            igf_min_fq,
        );
        // set up IGF grid for TCX 10 (transfac = 0.5)
        igf_grid_set_up(
            &mut igf_info.grid[IGF_GRID_LB_SHORT as usize],
            bit_rate_index,
            sample_rate,
            frame_length,
            8192, // 0.50f Q14
            igf_min_fq,
        );
    }

    ret_value
}

/// The cumulative-frequency tables and offsets `IGFCommonFuncsIGFGetCFTables` selects for the SCF
/// arithmetic coder; the reference writes them through eight out-pointers.
#[derive(Debug, Clone, Copy)]
pub struct IgfCfTables {
    /// `cf_se00`: CF table for t == 0 and f == 0
    pub cf_se00: &'static [i16],
    /// `cf_se01`: CF table for t == 0 and f == 1
    pub cf_se01: &'static [i16],
    /// `cf_off_se01`: offset for the CF table above
    pub cf_off_se01: i16,
    /// `cf_se02`: CF tables for t == 0 and f >= 2
    pub cf_se02: &'static [i16],
    /// `cf_off_se02`: offsets for the CF tables above
    pub cf_off_se02: &'static [i16],
    /// `cf_se10`: CF table for t == 1 and f == 0
    pub cf_se10: &'static [i16],
    /// `cf_off_se10`: offset for the CF table above
    pub cf_off_se10: i16,
    /// `cf_se11`: CF tables for t == 1 and f >= 1
    pub cf_se11: &'static [i16],
    /// `cf_off_se11`: offsets for the CF tables above
    pub cf_off_se11: &'static [i16],
}

impl IgfCfTables {
    /// No table selected (the pointers the reference leaves NULL).
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            cf_se00: &[],
            cf_se01: &[],
            cf_off_se01: 0,
            cf_se02: &[],
            cf_off_se02: &[],
            cf_se10: &[],
            cf_off_se10: 0,
            cf_se11: &[],
            cf_off_se11: &[],
        }
    }

    /// The tables of one row of the per-bit-rate tables (`bitRateIndex` in the SWB range); the
    /// ones shared by every bit rate are the same for all rows.
    fn for_row(bit_rate_index: usize) -> Self {
        Self {
            cf_se00: &CF_SE00_TAB,
            cf_se01: &CF_SE01_TAB[bit_rate_index],
            cf_off_se01: CF_OFF_SE01_TAB[bit_rate_index],
            cf_se02: CF_SE02_TAB[bit_rate_index].as_flattened(),
            cf_off_se02: &CF_OFF_SE02_TAB[bit_rate_index],
            cf_se10: &CF_SE10_TAB,
            cf_off_se10: CF_OFF_SE10_TAB,
            cf_se11: CF_SE11_TAB.as_flattened().as_flattened(),
            cf_off_se11: CF_OFF_SE11_TAB.as_flattened(),
        }
    }
}

/// `IGFCommonFuncsIGFGetCFTables`: select the cumulative-frequency tables and offsets of the SCF
/// arithmetic coder for a bit rate and bandwidth mode. Returns 1, or 0 (leaving `tables` as it
/// was) when the bit rate has no IGF configuration.
pub fn igf_common_funcs_igf_get_cf_tables(
    bit_rate: i32,
    mode: i16,
    rf_mode: i16,
    tables: &mut IgfCfTables,
) -> i16 {
    let mut ret_value = 0; // bitrate index is unknown -> error!
    let mut bit_rate_index = igf_map_bit_rate_to_index(bit_rate, mode, rf_mode);

    if sub(bit_rate_index, IGF_BITRATE_UNKNOWN) != 0 {
        ret_value = 1; // no error
        match bit_rate_index {
            IGF_BITRATE_WB_9600
            | IGF_BITRATE_RF_WB_13200
            | IGF_BITRATE_SWB_9600
            | IGF_BITRATE_SWB_13200
            | IGF_BITRATE_RF_SWB_13200
            | IGF_BITRATE_SWB_16400
            | IGF_BITRATE_SWB_24400
            | IGF_BITRATE_SWB_32000
            | IGF_BITRATE_SWB_48000 => {}
            IGF_BITRATE_FB_16400 | IGF_BITRATE_FB_24400 | IGF_BITRATE_FB_32000 => {
                bit_rate_index = add(
                    sub(bit_rate_index, IGF_BITRATE_FB_16400),
                    IGF_BITRATE_SWB_16400,
                );
            }
            IGF_BITRATE_FB_48000 => {
                bit_rate_index = add(
                    sub(bit_rate_index, IGF_BITRATE_FB_48000),
                    IGF_BITRATE_SWB_48000,
                );
            }
            IGF_BITRATE_FB_96000 | IGF_BITRATE_FB_128000 => {
                bit_rate_index = IGF_BITRATE_SWB_48000;
            }
            // IGF_BITRATE_UNKNOWN is excluded above and the reference asserts on any other index
            _ => return 0,
        }
        *tables = IgfCfTables::for_row(bit_rate_index as usize);
    }
    ret_value
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evs::cnst::{IGF_GRID_LB_NORM, SWB};

    #[test]
    fn trans_fac_one_returns_the_value_and_other_factors_round_to_even() {
        assert_eq!(igf_apply_trans_fac(48, 0x4000), 48);
        // 1.25 * 32 = 40, 0.5 * 32 = 16
        assert_eq!(igf_apply_trans_fac(32, 20480), 40);
        assert_eq!(igf_apply_trans_fac(32, 8192), 16);
        // 0.5 * 25 = 12.5 -> rounds to 13, then up to the even 14
        assert_eq!(igf_apply_trans_fac(25, 8192), 14);
    }

    #[test]
    fn bit_rate_index_follows_the_mode_and_the_rf_flag() {
        assert_eq!(
            igf_map_bit_rate_to_index(9600, IGF_MODE_WB, 0),
            IGF_BITRATE_WB_9600
        );
        assert_eq!(
            igf_map_bit_rate_to_index(13200, IGF_MODE_WB, 1),
            IGF_BITRATE_RF_WB_13200
        );
        assert_eq!(
            igf_map_bit_rate_to_index(13200, IGF_MODE_WB, 0),
            IGF_BITRATE_UNKNOWN
        );
        assert_eq!(
            igf_map_bit_rate_to_index(13200, IGF_MODE_SWB, 1),
            IGF_BITRATE_RF_SWB_13200
        );
        assert_eq!(
            igf_map_bit_rate_to_index(128000, IGF_MODE_FB, 0),
            IGF_BITRATE_FB_128000
        );
        assert_eq!(igf_map_bit_rate_to_index(5900, SWB, 0), IGF_BITRATE_UNKNOWN);
    }

    #[test]
    fn configuration_of_an_unknown_rate_reports_the_error() {
        let mut info = IgfInfo::zeroed();
        assert_eq!(
            igf_common_funcs_igf_configuration(5900, IGF_MODE_SWB, &mut info, 0),
            0
        );
        assert_eq!(info.bit_rate_index, IGF_BITRATE_UNKNOWN);
    }

    #[test]
    fn configuration_sets_up_all_three_grids() {
        let mut info = IgfInfo::zeroed();
        assert_eq!(
            igf_common_funcs_igf_configuration(24400, IGF_MODE_SWB, &mut info, 0),
            1
        );
        let grid = &info.grid[IGF_GRID_LB_NORM as usize];
        assert_eq!(grid.n_tiles, 3);
        assert_eq!(grid.stop_sfb, grid.swb_offset_len - 1);
        assert_eq!(grid.tile[0], grid.start_line);
        assert_eq!(info.grid[1].info_trans_fac, 20480);
        assert_eq!(info.grid[2].info_trans_fac, 8192);
    }

    #[test]
    fn cf_tables_of_the_fb_rates_share_the_swb_rows() {
        let mut fb = IgfCfTables::empty();
        let mut swb = IgfCfTables::empty();
        assert_eq!(
            igf_common_funcs_igf_get_cf_tables(16400, IGF_MODE_FB, 0, &mut fb),
            1
        );
        assert_eq!(
            igf_common_funcs_igf_get_cf_tables(16400, IGF_MODE_SWB, 0, &mut swb),
            1
        );
        assert_eq!(fb.cf_se01, swb.cf_se01);
        assert_eq!(fb.cf_off_se02, swb.cf_off_se02);
        let mut none = IgfCfTables::empty();
        assert_eq!(
            igf_common_funcs_igf_get_cf_tables(7200, IGF_MODE_FB, 0, &mut none),
            0
        );
        assert!(none.cf_se00.is_empty());
    }

    #[test]
    fn square_spectrum_writes_at_the_offset() {
        let spectrum = [0, 0, 0x4000_0000, -0x2000_0000, 0];
        let mut squared = [0i32; 8];
        let mut exponent = 0;
        igf_common_funcs_mdct_square_spec(2, 4, &spectrum, 3, &mut squared, &mut exponent, 1);
        assert_eq!(squared[0], 0);
        assert_ne!(squared[3], 0);
        assert_ne!(squared[4], 0);
        assert_eq!(squared[5], 0);
    }

    #[test]
    fn sfb_energy_without_a_spectrum_is_zero() {
        let mut energy = [7i32; 4];
        let mut exponent = [5i16; 4];
        igf_common_funcs_calc_sfb_energy_power_spec(
            0,
            3,
            &[0, 2, 4, 6, 8],
            None,
            &0,
            &mut energy,
            &mut exponent,
        );
        assert_eq!(energy, [0, 0, 0, 7]);
        assert_eq!(exponent, [5; 4]);
    }
}
