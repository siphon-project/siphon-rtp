//! `lib_dec/pvq_core_dec_fx.c` against `fn_pvq_core_dec`: `pvq_core_dec_fx` on GSC and HQ band
//! layouts (through `pvq_decode_frame_fx`, `pvq_decode_band_fx`, `get_pvq_splits_fx`,
//! `decode_energies_fx` and `densitySymbolIndexDecode_fx`), and `decode_energies_fx` alone.

use siphon_rtp_codec::evs::dec::pvq_core_dec::{
    decode_energies, density_symbol_index_decode, pvq_core_dec,
};
use siphon_rtp_codec::evs::dec::range_dec::rc_dec_init;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn new_state(case: &Case) -> Box<DecoderState> {
    let mut st = Box::new(DecoderState::zeroed());
    let bits = case.i16s("bits");
    for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
        *slot = bit as u16;
    }
    st.total_num_bits = bits.len() as i16;
    st
}

fn check_rc(case: &Case, st: &DecoderState) {
    let rc = vec![st.rc_low as i32, st.rc_range as i32, st.rc_help as i32];
    check(case, "rc", &rc, &case.out_i32s("rc"));
    let s = vec![
        st.rc_num_bits,
        st.rc_offset,
        st.rc_end,
        st.next_bit_pos,
        st.ber_detect,
        st.ber_occured_in_pvq,
    ];
    check(case, "st", &s, &case.out_i16s("st"));
}

#[test]
fn pvq_core_dec_matches_the_reference() {
    let Some(cases) = corpus("pvq_core_dec", "pvq_core_dec") else {
        return;
    };
    for case in &cases {
        let mut st = new_state(case);
        let nb_sfm = case.i16("nb_sfm");
        let sfm_end = case.i16s("sfm_end");
        let total = *sfm_end.last().unwrap_or(&0) as usize;
        let mut coefs = vec![-9i16; 960];
        let mut r = case.i16s("r");
        let mut rs = case.i16s("rs");
        let mut npulses = vec![0i16; 44];
        let mut maxpulse = vec![-9i16; 44];
        let mut q = -1;
        let use_rs = case.i16("use_rs") != 0;
        let ret = pvq_core_dec(
            &mut st,
            &case.i16s("sfm_start"),
            &sfm_end,
            &case.i16s("sfmsize"),
            &mut coefs,
            &mut q,
            case.i16("bits_tot"),
            nb_sfm,
            &mut r,
            if use_rs { Some(&mut rs) } else { None },
            &mut npulses,
            &mut maxpulse,
            case.i16("core"),
        );
        let n = nb_sfm as usize;
        check(case, "ret", &ret, &case.out_i16("ret"));
        check(case, "q", &q, &case.out_i16("q"));
        check(
            case,
            "coefs",
            &coefs[..total].to_vec(),
            &case.out_i16s("coefs"),
        );
        check(case, "r", &r, &case.out_i16s("r"));
        check(case, "rs", &rs, &case.out_i16s("rs"));
        check(
            case,
            "npulses",
            &npulses[..n].to_vec(),
            &case.out_i16s("npulses"),
        );
        check(
            case,
            "maxpulse",
            &maxpulse[..n].to_vec(),
            &case.out_i16s("maxpulse"),
        );
        check_rc(case, &st);
    }
}

#[test]
fn decode_energies_matches_the_reference() {
    let Some(cases) = corpus("pvq_core_dec", "decode_energies") else {
        return;
    };
    for case in &cases {
        let mut st = new_state(case);
        let dim = case.i16("dim");
        let np = case.i16("np");
        let mut dim_part = [0i16; 11];
        let parts = dim / np;
        for part in dim_part.iter_mut().take(np as usize - 1) {
            *part = parts;
        }
        dim_part[np as usize - 1] = dim - parts * (np - 1);
        let mut bits_part = [-9i16; 11];
        let mut g_part = [-32768i16; 10];
        let mut bits_left = case.i16("bits_left");
        rc_dec_init(&mut st, case.i16("pvq_bits"));
        decode_energies(
            &mut st,
            np,
            &dim_part,
            &mut bits_part,
            &mut g_part,
            case.i16("qband"),
            &mut bits_left,
            dim,
            case.i16("strict"),
        );
        check(
            case,
            "bits_part",
            &bits_part.to_vec(),
            &case.out_i16s("bits_part"),
        );
        check(case, "g_part", &g_part.to_vec(), &case.out_i16s("g_part"));
        check(case, "bits_left", &bits_left, &case.out_i16("bits_left"));
        check_rc(case, &st);
    }
}

#[test]
fn density_symbol_index_decode_matches_the_reference() {
    let Some(cases) = corpus("pvq_core_dec", "density_symbol") else {
        return;
    };
    for case in &cases {
        let mut st = new_state(case);
        rc_dec_init(&mut st, case.i16("pvq_bits"));
        let mut index_phi = -7;
        density_symbol_index_decode(
            &mut st,
            case.i16("density"),
            case.i16("opp"),
            case.i16("near"),
            &mut index_phi,
        );
        check(case, "index_phi", &index_phi, &case.out_i16("index_phi"));
        check_rc(case, &st);
    }
}
