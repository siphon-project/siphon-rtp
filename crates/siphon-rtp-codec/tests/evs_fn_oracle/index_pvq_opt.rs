//! `lib_com/index_pvq_opt_fx.c` against `fn_index_pvq_opt`. The static helpers (`a_bwd_fx`,
//! `direct_row_A2U_rec_calc_fx`, the exact divisions, `nm_h_prep_opt_fx`, `mind2vec_*`,
//! `setval_update_sign_fx`, `get_lead_sign_fx`) are proven through the two entry points: the
//! offset table after `get_size_mpvq_calc_offset_fx` and after decoding is compared in full.

use siphon_rtp_codec::evs::com::index_pvq_opt::{
    get_size_mpvq_calc_offset, mpvq_decode_vec, PvqEntry,
};

use crate::common::{corpus, mismatch, Case};

fn check_h(case: &Case, dim: i16, k: i16, h: &[u32]) {
    let count = if dim > 5 { k as usize + 2 } else { 1 };
    let rust: Vec<i64> = h[..count].iter().map(|&v| i64::from(v)).collect();
    if let Some(message) = mismatch(case, "h", &rust, &case.outputs["h"]) {
        panic!("{message}");
    }
}

#[test]
fn mpvq_size_and_offsets_match_the_reference() {
    let Some(cases) = corpus("index_pvq_opt", "size") else {
        return;
    };
    for case in &cases {
        let (dim, k) = (case.i16("dim"), case.i16("k"));
        let mut h = vec![0u32; 514];
        let entry = get_size_mpvq_calc_offset(dim, k, &mut h);
        let rust = (i64::from(entry.size), entry.dim, entry.k_val);
        let reference = (
            case.outputs["size"][0],
            case.out_i16("e_dim"),
            case.out_i16("e_k"),
        );
        if let Some(message) = mismatch(case, "size/dim/k", &rust, &reference) {
            panic!("{message}");
        }
        check_h(case, dim, k, &h);
    }
}

#[test]
fn mpvq_decode_vec_matches_the_reference() {
    let Some(cases) = corpus("index_pvq_opt", "decode") else {
        return;
    };
    for case in &cases {
        let (dim, k) = (case.i16("dim"), case.i16("k"));
        let mut h = vec![0u32; 514];
        let mut entry: PvqEntry = get_size_mpvq_calc_offset(dim, k, &mut h);
        entry.index = case.inputs["index"][0] as u32;
        entry.lead_sign_ind = case.i16("lead_sign_ind");
        let mut vec = [7i16; 64];
        mpvq_decode_vec(&entry, &mut h, &mut vec);
        if let Some(message) = mismatch(
            case,
            "vec",
            &vec[..dim as usize].to_vec(),
            &case.out_i16s("vec"),
        ) {
            panic!("{message}");
        }
        check_h(case, dim, k, &h);
    }
}

/// `getSqrtWord32` (ported in `basop_util`) over the domain `mind2vec_three` feeds it (2·index - 1
/// for up to 512 pulses) and up to 2^30.
#[test]
fn integer_square_root_matches_get_sqrt_word32() {
    let Some(cases) = corpus("index_pvq_opt", "sqrt") else {
        return;
    };
    for case in &cases {
        let val = case.i32("val");
        let root = siphon_rtp_codec::evs::com::basop_util::get_sqrt_word32(val);
        if let Some(message) = mismatch(case, "root", &root, &case.out_i16("root")) {
            panic!("{message}");
        }
    }
}
