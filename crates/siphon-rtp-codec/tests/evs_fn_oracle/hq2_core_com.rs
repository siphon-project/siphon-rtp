//! `lib_com/hq2_core_com_fx.c` against `fn_hq2_core_com`.

use siphon_rtp_codec::evs::cnst::BANDS_MAX;
use siphon_rtp_codec::evs::com::hq2_core_com::{
    bit_allocation_second, hq2_core_configure, mdct_spectrum_denorm,
    reverse_transient_frame_energies, spt_shorten_domain_band_restore,
    spt_shorten_domain_band_save, spt_shorten_domain_pre, spt_swb_peakpos_tmp_save,
};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

/// The band layout and parameters `hq2_core_configure` gives for the case's inputs.
pub struct Config {
    pub bands: i16,
    pub length: i16,
    pub band_width: Vec<i16>,
    pub band_start: Vec<i16>,
    pub band_end: Vec<i16>,
    pub qint: i32,
    pub eref: i16,
    pub bit_alloc_weight: i16,
    pub gqlevs: i16,
    pub ngq: i16,
    pub p2a_bands: i16,
    pub p2a_th: i16,
    pub pd_thresh: i16,
    pub ld_slope: i16,
    pub ni_coef: i16,
}

pub fn configure(case: &Case) -> Config {
    let mut c = Config {
        bands: 0,
        length: 0,
        band_width: vec![0; BANDS_MAX as usize],
        band_start: vec![0; BANDS_MAX as usize],
        band_end: vec![0; BANDS_MAX as usize],
        qint: 0,
        eref: 0,
        bit_alloc_weight: 0,
        gqlevs: 0,
        ngq: 0,
        p2a_bands: 0,
        p2a_th: 0,
        pd_thresh: 0,
        ld_slope: 0,
        ni_coef: 0,
    };
    hq2_core_configure(
        case.i16("frame_length"),
        case.i16("num_bits"),
        case.i16("is_transient"),
        &mut c.bands,
        &mut c.length,
        &mut c.band_width,
        &mut c.band_start,
        &mut c.band_end,
        &mut c.qint,
        &mut c.eref,
        &mut c.bit_alloc_weight,
        &mut c.gqlevs,
        &mut c.ngq,
        &mut c.p2a_bands,
        &mut c.p2a_th,
        &mut c.pd_thresh,
        &mut c.ld_slope,
        &mut c.ni_coef,
        case.i32("bwe_br"),
    );
    let bands = c.bands as usize;
    c.band_width.truncate(bands);
    c.band_start.truncate(bands);
    c.band_end.truncate(bands);
    c
}

#[test]
fn hq2_core_configure_matches_the_reference() {
    let Some(cases) = corpus("hq2_core_com", "hq2_core_configure") else {
        return;
    };
    for case in &cases {
        let c = configure(case);
        check(case, "bands", &c.bands, &case.out_i16("bands"));
        check(case, "length", &c.length, &case.out_i16("length"));
        check(
            case,
            "band_width",
            &c.band_width,
            &case.out_i16s("band_width"),
        );
        check(
            case,
            "band_start",
            &c.band_start,
            &case.out_i16s("band_start"),
        );
        check(case, "band_end", &c.band_end, &case.out_i16s("band_end"));
        check(case, "qint", &c.qint, &case.out_i32("qint"));
        let scalars = [
            c.eref,
            c.bit_alloc_weight,
            c.gqlevs,
            c.ngq,
            c.p2a_bands,
            c.p2a_th,
            c.pd_thresh,
            c.ld_slope,
            c.ni_coef,
        ];
        let names = [
            "eref",
            "bit_alloc_weight",
            "gqlevs",
            "ngq",
            "p2a_bands",
            "p2a_th",
            "pd_thresh",
            "ld_slope",
            "ni_coef",
        ];
        for (value, name) in scalars.iter().zip(names) {
            check(case, name, value, &case.out_i16(name));
        }
    }
}

#[test]
fn mdct_spectrum_denorm_matches_the_reference() {
    let Some(cases) = corpus("hq2_core_com", "mdct_spectrum_denorm") else {
        return;
    };
    for case in &cases {
        let c = configure(case);
        let mut y2 = case.i32s("y2");
        mdct_spectrum_denorm(
            &case.i16s("inp"),
            &mut y2,
            &c.band_start,
            &c.band_end,
            &c.band_width,
            &case.i32s("energy"),
            &case.i16s("npulses"),
            c.bands,
            c.ld_slope,
            c.pd_thresh,
        );
        check(case, "y2", &y2, &case.out_i32s("y2"));
    }
}

#[test]
fn reverse_transient_frame_energies_matches_the_reference() {
    let Some(cases) = corpus("hq2_core_com", "reverse_transient_frame_energies") else {
        return;
    };
    for case in &cases {
        let mut energy = case.i32s("energy");
        let bands = energy.len() as i16;
        reverse_transient_frame_energies(&mut energy, bands);
        check(case, "energy", &energy, &case.out_i32s("energy"));
    }
}

#[test]
fn bit_allocation_second_matches_the_reference() {
    let Some(cases) = corpus("hq2_core_com", "bit_allocation_second") else {
        return;
    };
    for case in &cases {
        let c = configure(case);
        let mut k_num = [-5_i16; 2];
        bit_allocation_second(
            &case.i32s("rk"),
            &case.i32s("rk_sort"),
            c.bands,
            &c.band_width,
            &case.i16s("k_sort"),
            &mut k_num,
            &case.i16s("p2a_flags"),
            c.p2a_bands,
            &case.i16s("last_bitalloc"),
            case.i16("input_frame"),
        );
        check(case, "k_num", &k_num.to_vec(), &case.out_i16s("k_num"));
    }
}

/// `spt_shorten_domain_band_save_fx`, `spt_shorten_domain_pre_fx` and
/// `spt_shorten_domain_band_restore_fx` in `hq_lr_dec_fx`'s order.
#[test]
fn spt_shorten_domain_matches_the_reference() {
    let Some(cases) = corpus("hq2_core_com", "spt_shorten_domain") else {
        return;
    };
    for case in &cases {
        let bands = case.i16("bands");
        let (start, end, width) = (
            case.i16s("band_start"),
            case.i16s("band_end"),
            case.i16s("band_width"),
        );
        let (mut os, mut oe, mut ow) = ([-7i16; 4], [-7i16; 4], [-7i16; 4]);
        let (mut ns, mut ne, mut nw) = ([-7i16; 4], [-7i16; 4], [-7i16; 4]);
        spt_shorten_domain_band_save(bands, &start, &end, &width, &mut os, &mut oe, &mut ow);
        spt_shorten_domain_pre(
            &start,
            &end,
            &case.i16s("peaks"),
            bands,
            case.i32("bwe_br"),
            &mut ns,
            &mut ne,
            &mut nw,
        );
        for (name, rust) in [
            ("os", os),
            ("oe", oe),
            ("ow", ow),
            ("ns", ns),
            ("ne", ne),
            ("nw", nw),
        ] {
            check(case, name, &rust.to_vec(), &case.out_i16s(name));
        }
        let mut start = case.out_i16s("moved_start");
        let mut end = case.out_i16s("moved_end");
        let mut width = case.out_i16s("moved_width");
        spt_shorten_domain_band_restore(bands, &mut start, &mut end, &mut width, &os, &oe, &ow);
        check(case, "band_start", &start, &case.out_i16s("band_start"));
        check(case, "band_end", &end, &case.out_i16s("band_end"));
        check(case, "band_width", &width, &case.out_i16s("band_width"));
    }
}

#[test]
fn spt_swb_peakpos_tmp_save_matches_the_reference() {
    let Some(cases) = corpus("hq2_core_com", "spt_swb_peakpos_tmp_save") else {
        return;
    };
    for case in &cases {
        let mut pos = [-7i16; 4];
        spt_swb_peakpos_tmp_save(
            &case.i32s("y2"),
            case.i16("bands"),
            &case.i16s("band_start"),
            &case.i16s("band_end"),
            &mut pos,
        );
        check(case, "pos", &pos.to_vec(), &case.out_i16s("pos"));
    }
}
