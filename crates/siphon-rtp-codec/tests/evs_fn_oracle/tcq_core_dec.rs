//! `lib_dec/tcq_core_dec_fx.c` against `fn_tcq_core_dec`: the whole low-rate TCQ / USQ spectrum
//! decode over configurations from `hq2_core_configure_fx` and allocations from
//! `hq2_bit_alloc_fx`, on random coded bits.

use siphon_rtp_codec::evs::dec::state::DecoderState;
use siphon_rtp_codec::evs::dec::tcq_core_dec::tcq_core_lr_dec;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn tcq_core_lr_dec_matches_the_reference() {
    let Some(cases) = corpus("tcq_core_dec", "tcq_core_lr_dec") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        let bits = case.i16s("bits");
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
            *slot = bit as u16;
        }
        st.total_num_bits = bits.len() as i16;
        st.codec_mode = 1;

        let bands = case.i16("bands");
        let mut rk = case.i32s("rk");
        let mut inp = vec![-7i16; 960];
        let mut npulses = vec![-7i16; bands as usize];
        let mut k_sort = vec![0i16; bands as usize];
        tcq_core_lr_dec(
            &mut st,
            &mut inp,
            case.i16("bit_budget"),
            bands,
            &case.i16s("band_start"),
            &case.i16s("band_width"),
            &mut rk,
            &mut npulses,
            &mut k_sort,
            &case.i16s("p2a_flags"),
            case.i16("p2a_bands"),
            &case.i16s("last_bitalloc"),
            case.i16("input_frame"),
            case.i16("adjust_flag"),
            case.i16("is_transient"),
        );
        let reference = case.out_i16s("inp");
        check(case, "inp", &inp[..reference.len()].to_vec(), &reference);
        check(case, "npulses", &npulses, &case.out_i16s("npulses"));
        check(case, "k_sort", &k_sort, &case.out_i16s("k_sort"));
        check(case, "rk", &rk, &case.out_i32s("rk"));
        check(
            case,
            "next_bit_pos",
            &st.next_bit_pos,
            &case.out_i16("next_bit_pos"),
        );
    }
}
