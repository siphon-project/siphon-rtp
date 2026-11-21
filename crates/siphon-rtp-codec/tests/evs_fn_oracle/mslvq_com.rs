//! `lib_com/mslvq_com_fx.c` against `fn_mslvq_com`.

use siphon_rtp_codec::evs::com::mslvq_com::{
    deindex_lvq, deindex_lvq_cng, divide_16_16, divide_32_32, divide_64_32, init_lvq,
};

use crate::common::{corpus, corpus_sized, mismatch};

struct Tables {
    offset_scale1: Vec<[i32; 4]>,
    offset_scale2: Vec<[i32; 4]>,
    offset_scale1_p: Vec<[i32; 4]>,
    offset_scale2_p: Vec<[i32; 4]>,
    no_scales: Vec<[i16; 2]>,
    no_scales_p: Vec<[i16; 2]>,
}

fn tables() -> Tables {
    let mut tables = Tables {
        offset_scale1: vec![[0; 4]; 129],
        offset_scale2: vec![[0; 4]; 129],
        offset_scale1_p: vec![[0; 4]; 146],
        offset_scale2_p: vec![[0; 4]; 146],
        no_scales: vec![[0; 2]; 128],
        no_scales_p: vec![[0; 2]; 145],
    };
    init_lvq(
        &mut tables.offset_scale1,
        &mut tables.offset_scale2,
        &mut tables.offset_scale1_p,
        &mut tables.offset_scale2_p,
        &mut tables.no_scales,
        &mut tables.no_scales_p,
    );
    tables
}

#[test]
fn init_lvq_matches_the_reference() {
    let Some(cases) = corpus_sized("mslvq_com", "init_lvq", 1) else {
        return;
    };
    let case = &cases[0];
    let t = tables();
    let flat32 = |rows: &[[i32; 4]]| rows.as_flattened().to_vec();
    let flat16 = |rows: &[[i16; 2]]| rows.as_flattened().to_vec();
    for (name, rust) in [
        ("offset_scale1", flat32(&t.offset_scale1)),
        ("offset_scale2", flat32(&t.offset_scale2)),
        ("offset_scale1_p", flat32(&t.offset_scale1_p)),
        ("offset_scale2_p", flat32(&t.offset_scale2_p)),
    ] {
        if let Some(message) = mismatch(case, name, &rust, &case.out_i32s(name)) {
            panic!("{message}");
        }
    }
    for (name, rust) in [
        ("no_scales", flat16(&t.no_scales)),
        ("no_scales_p", flat16(&t.no_scales_p)),
    ] {
        if let Some(message) = mismatch(case, name, &rust, &case.out_i16s(name)) {
            panic!("{message}");
        }
    }
}

#[test]
fn deindex_lvq_matches_the_reference() {
    let Some(cases) = corpus("mslvq_com", "deindex_lvq") else {
        return;
    };
    let t = tables();
    for case in &cases {
        let mut index = case.i16s("index");
        let mut x_lvq = [0i16; 16];
        let sf_flag = case.i16("sf_flag");
        let (scale1, scale2, no_scales) = if sf_flag == 1 {
            (&t.offset_scale1, &t.offset_scale2, &t.no_scales)
        } else {
            (&t.offset_scale1_p, &t.offset_scale2_p, &t.no_scales_p)
        };
        // The oracle prefills x_lvq with noise the function overwrites on every path; any
        // left-over would show as a mismatch.
        let ber = deindex_lvq(
            &mut index,
            &mut x_lvq,
            case.i16("mode"),
            sf_flag,
            case.i16("no_bits"),
            scale1.as_flattened(),
            scale2.as_flattened(),
            no_scales.as_flattened(),
        );
        if let Some(message) = mismatch(case, "ber", &ber, &case.out_i16("ber")) {
            panic!("{message}");
        }
        if let Some(message) = mismatch(case, "x_lvq", &x_lvq.to_vec(), &case.out_i16s("x_lvq")) {
            panic!("{message}");
        }
        if let Some(message) = mismatch(case, "index", &index, &case.out_i16s("index")) {
            panic!("{message}");
        }
    }
}

#[test]
fn deindex_lvq_cng_matches_the_reference() {
    let Some(cases) = corpus("mslvq_com", "deindex_lvq_cng") else {
        return;
    };
    let t = tables();
    for case in &cases {
        let mut index = case.i16s("index");
        let mut x_lvq = [0i16; 16];
        let ber = deindex_lvq_cng(
            &mut index,
            &mut x_lvq,
            case.i16("idx_cv"),
            25,
            t.offset_scale1.as_flattened(),
            t.offset_scale2.as_flattened(),
            t.no_scales.as_flattened(),
        );
        if let Some(message) = mismatch(case, "ber", &ber, &case.out_i16("ber")) {
            panic!("{message}");
        }
        if let Some(message) = mismatch(case, "x_lvq", &x_lvq.to_vec(), &case.out_i16s("x_lvq")) {
            panic!("{message}");
        }
        if let Some(message) = mismatch(case, "index", &index, &case.out_i16s("index")) {
            panic!("{message}");
        }
    }
}

#[test]
fn integer_divisions_match_the_reference() {
    let Some(cases) = corpus("mslvq_com", "divide") else {
        return;
    };
    for case in &cases {
        let (q, rem) = divide_32_32(case.i32("y"), case.i32("x"));
        let (q16, rem16) = divide_16_16(case.i16("y16"), case.i16("x16"));
        let (q64, rem64) = divide_64_32(&case.i16s("xs"), case.i32("x64"));
        let rust = [q, rem, q16.into(), rem16.into(), q64, rem64];
        let reference = [
            case.out_i32("q"),
            case.out_i32("rem"),
            case.out_i32("q16"),
            case.out_i32("rem16"),
            case.out_i32("q64"),
            case.out_i32("rem64"),
        ];
        if let Some(message) = mismatch(case, "q/rem/q16/rem16/q64/rem64", &rust, &reference) {
            panic!("{message}");
        }
    }
}
