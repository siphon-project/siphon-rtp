//! Configuration of the HQ core per frame length, class and bit rate (TS 26.442
//! `lib_com/hq_conf_fx.c`; TS 26.445 §6.2.2.3).

use crate::evs::cnst::{
    HQ_16K40, HQ_24K40, HQ_32K, HQ_GENERIC_FOFFSET_24K4, HQ_GENERIC_FOFFSET_32K, HQ_GEN_FB,
    HQ_GEN_SWB, HQ_HARMONIC, HQ_HVQ, HVQ_THRES_SFM_24K, HVQ_THRES_SFM_32K, L_FRAME32K, L_FRAME48K,
    NB_SFM, NORMI_BITS, SFM_N_HARM, SFM_N_HARM_FB, SFM_N_STA_10K, SFM_N_STA_8K, SFM_N_SWB,
    SFM_N_WB,
};
use crate::evs::rom::{
    BAND_END_HARM, BAND_END_HQ, BAND_END_WB, BAND_LEN_HARM, BAND_LEN_HQ, BAND_LEN_WB,
    BAND_START_HARM, BAND_START_HQ, BAND_START_WB,
};
use crate::itu::basic_ops::{extract_l, sub};
use crate::itu::stl2009::l_mult0;

/// The band table a configuration selects: widths, first and last coefficient of every band.
#[derive(Clone, Copy)]
struct BandTables {
    sfmsize: &'static [i16],
    sfm_start: &'static [i16],
    sfm_end: &'static [i16],
}

const TABLES_HQ: BandTables = BandTables {
    sfmsize: &BAND_LEN_HQ,
    sfm_start: &BAND_START_HQ,
    sfm_end: &BAND_END_HQ,
};
const TABLES_HARM: BandTables = BandTables {
    sfmsize: &BAND_LEN_HARM,
    sfm_start: &BAND_START_HARM,
    sfm_end: &BAND_END_HARM,
};
const TABLES_WB: BandTables = BandTables {
    sfmsize: &BAND_LEN_WB,
    sfm_start: &BAND_START_WB,
    sfm_end: &BAND_END_WB,
};

/// `hq_configure_fx`: the band layout of one HQ frame. `num_sfm` / `nb_sfm` are the total and
/// coded band counts, `start_norm` the first SDE-coded norm, `num_env_bands` the coded envelope
/// bands, `numnrmibits` the bits of the fall-back norm coding, `hq_generic_offset` the HQ GENERIC
/// frequency offset (left untouched where the reference leaves it unset) and
/// `sfmsize` / `sfm_start` / `sfm_end` the band tables.
pub fn hq_configure(
    length: i16,
    hqswb_clas: i16,
    core_brate: i32,
    num_sfm: &mut i16,
    nb_sfm: &mut i16,
    start_norm: &mut i16,
    num_env_bands: &mut i16,
    numnrmibits: &mut i16,
    hq_generic_offset: &mut i16,
    sfmsize: &mut &'static [i16],
    sfm_start: &mut &'static [i16],
    sfm_end: &mut &'static [i16],
) {
    *start_norm = 0;
    let tables;
    if sub(length, L_FRAME48K) == 0 {
        if sub(hqswb_clas, HQ_GEN_FB) == 0 {
            *num_sfm = NB_SFM;
            tables = TABLES_HQ;
            if core_brate == i32::from(HQ_32K) {
                *hq_generic_offset = HQ_GENERIC_FOFFSET_32K;
            } else if core_brate == i32::from(HQ_16K40) || core_brate == i32::from(HQ_24K40) {
                *hq_generic_offset = HQ_GENERIC_FOFFSET_24K4;
            }
            // setting start frequency of FD BWE
            if core_brate == i32::from(HQ_32K) {
                *num_env_bands = SFM_N_STA_10K;
            } else if core_brate == i32::from(HQ_16K40) || core_brate == i32::from(HQ_24K40) {
                *num_env_bands = SFM_N_STA_8K;
            }
            *nb_sfm = *num_sfm;
        } else if sub(hqswb_clas, HQ_HARMONIC) == 0 {
            *num_sfm = SFM_N_HARM_FB;
            *nb_sfm = SFM_N_HARM_FB;
            *num_env_bands = SFM_N_HARM_FB;
            tables = TABLES_HARM;
        } else if sub(hqswb_clas, HQ_HVQ) == 0 {
            *num_sfm = SFM_N_HARM_FB;
            hq_configure_hvq(core_brate, *num_sfm, nb_sfm, num_env_bands, start_norm);
            tables = TABLES_HARM;
        } else {
            *num_sfm = NB_SFM;
            *nb_sfm = *num_sfm;
            *num_env_bands = NB_SFM;
            tables = TABLES_HQ;
        }
    } else if sub(length, L_FRAME32K) == 0 {
        if sub(hqswb_clas, HQ_HARMONIC) == 0 {
            *num_sfm = SFM_N_HARM;
            *nb_sfm = SFM_N_HARM;
            *num_env_bands = SFM_N_HARM;
            tables = TABLES_HARM;
        } else if sub(hqswb_clas, HQ_HVQ) == 0 {
            *num_sfm = SFM_N_HARM;
            hq_configure_hvq(core_brate, *num_sfm, nb_sfm, num_env_bands, start_norm);
            tables = TABLES_HARM;
        } else if sub(hqswb_clas, HQ_GEN_SWB) == 0 {
            *num_sfm = SFM_N_SWB;
            tables = TABLES_HQ;
            if core_brate == i32::from(HQ_32K) {
                *hq_generic_offset = HQ_GENERIC_FOFFSET_32K;
            } else if core_brate == i32::from(HQ_24K40) {
                *hq_generic_offset = HQ_GENERIC_FOFFSET_24K4;
            }
            // setting start frequency of HQ Generic
            if core_brate == i32::from(HQ_32K) {
                *num_env_bands = SFM_N_STA_10K;
            } else if core_brate == i32::from(HQ_24K40) {
                *num_env_bands = SFM_N_STA_8K;
            }
            *nb_sfm = *num_sfm;
        } else {
            // HQ_NORMAL and HQ_TRANSIENT
            *num_sfm = SFM_N_SWB;
            *nb_sfm = *num_sfm;
            *num_env_bands = SFM_N_SWB;
            tables = TABLES_HQ;
        }
    } else {
        *num_sfm = SFM_N_WB;
        *nb_sfm = *num_sfm;
        *num_env_bands = SFM_N_WB;
        tables = TABLES_WB;
    }
    *sfmsize = tables.sfmsize;
    *sfm_start = tables.sfm_start;
    *sfm_end = tables.sfm_end;
    *numnrmibits = extract_l(l_mult0(sub(*num_env_bands, 1), NORMI_BITS));
}

/// The HVQ branch shared by the 32 kHz and 48 kHz layouts: only the bands past
/// `HVQ_THRES_SFM_*` carry norms.
fn hq_configure_hvq(
    core_brate: i32,
    num_sfm: i16,
    nb_sfm: &mut i16,
    num_env_bands: &mut i16,
    start_norm: &mut i16,
) {
    if core_brate == i32::from(HQ_24K40) {
        *nb_sfm = HVQ_THRES_SFM_24K;
        *num_env_bands = sub(num_sfm, *nb_sfm);
        *start_norm = HVQ_THRES_SFM_24K;
    } else {
        *nb_sfm = HVQ_THRES_SFM_32K;
        *num_env_bands = sub(num_sfm, *nb_sfm);
        *start_norm = HVQ_THRES_SFM_32K;
    }
}
