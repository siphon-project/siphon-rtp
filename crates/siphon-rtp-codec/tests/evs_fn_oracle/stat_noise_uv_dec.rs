//! `lib_dec/stat_noise_uv_dec_fx.c` against `fn_stat_noise_uv_dec`: `stat_noise_uv_dec_fx` over
//! runs of consecutive frames on one decoder state.

use siphon_rtp_codec::evs::dec::stat_noise_uv_dec::stat_noise_uv_dec;
use siphon_rtp_codec::evs::dec::state::DecoderState;

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

fn load_state(case: &Case, st: &mut DecoderState) {
    let s = case.i16s("st");
    st.unv_cnt = s[0];
    st.lp_gainc = s[1];
    st.uv_count = s[2];
    st.act_count = s[3];
    st.noimix_seed = s[4];
    st.min_alpha = s[5];
    st.exc_pe = s[6];
    st.q_stat_noise = s[7];
    st.q_stat_noise_ge = s[8];
    st.next_bit_pos = s[9];
    let l = case.i32s("l");
    st.lp_ener = l[0];
    st.ge_sm = l[1];
    st.lsp_cng.copy_from_slice(&case.i16s("lspcng"));
    st.lspold_s.copy_from_slice(&case.i16s("lspold_s"));
}

fn check_state(case: &Case, st: &DecoderState) {
    let s = vec![
        st.unv_cnt,
        st.lp_gainc,
        st.uv_count,
        st.act_count,
        st.noimix_seed,
        st.min_alpha,
        st.exc_pe,
        st.q_stat_noise,
        st.q_stat_noise_ge,
        st.next_bit_pos,
    ];
    check(case, "st", &s, &case.out_i16s("st"));
    check(case, "l", &vec![st.lp_ener, st.ge_sm], &case.out_i32s("l"));
    check(
        case,
        "lspcng",
        &st.lsp_cng.to_vec(),
        &case.out_i16s("lspcng"),
    );
    check(
        case,
        "lspold_s",
        &st.lspold_s.to_vec(),
        &case.out_i16s("lspold_s"),
    );
}

#[test]
fn stat_noise_uv_dec_matches_the_reference() {
    let Some(cases) = corpus("stat_noise_uv_dec", "stat_noise_uv_dec") else {
        return;
    };
    for case in &cases {
        let mut st = Box::new(DecoderState::zeroed());
        let bits = case.i16s("bits");
        for (slot, &bit) in st.bit_stream.iter_mut().zip(&bits) {
            *slot = bit as u16;
        }
        st.total_num_bits = bits.len() as i16;
        st.lsp_old.copy_from_slice(&case.i16s("lsp_old"));
        st.opt_amr_wb = case.i16("amr");
        st.bwidth = case.i16("bwidth");
        load_state(case, &mut st);
        for f in 0..case.i32("frames") {
            let params = case.i16s(&format!("f{f}"));
            st.core_brate = i32::from(params[1]) * 100;
            st.q_exc = params[2];
            let mut aq = vec![-5i16; 4 * 17];
            let mut exc2 = case.i16s(&format!("exc{f}"));
            stat_noise_uv_dec(
                &mut st,
                params[0],
                &case.i16s(&format!("new{f}")),
                &case.i16s(&format!("mid{f}")),
                &mut aq,
                &mut exc2,
            );
            check(
                case,
                &format!("aq{f}"),
                &aq,
                &case.out_i16s(&format!("aq{f}")),
            );
            check(
                case,
                &format!("exc{f}"),
                &exc2,
                &case.out_i16s(&format!("exc{f}")),
            );
        }
        check_state(case, &st);
    }
}
