//! `lib_dec/lsf_dec_fx.c` against `fn_lsf_dec`: `lsf_dec_fx` over runs of consecutive MODE1
//! frames on one decoder state (SID frames included, reaching `dqlsf_CNG_fx`; every frame reaching
//! `lsf_end_dec_fx` and `lsf_mid_dec_fx`), and `lsf_end_dec_fx`'s MODE2 path.

use siphon_rtp_codec::evs::com::mslvq_com::init_lvq;
use siphon_rtp_codec::evs::dec::lsf_dec::{lsf_dec, lsf_end_dec};
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
    let st_ref = &mut *st;
    init_lvq(
        &mut st_ref.offset_scale1,
        &mut st_ref.offset_scale2,
        &mut st_ref.offset_scale1_p,
        &mut st_ref.offset_scale2_p,
        &mut st_ref.no_scales,
        &mut st_ref.no_scales_p,
    );
    let s = case.i16s("st");
    st.ber_detect = s[0];
    st.next_bit_pos = s[1];
    st.safety_net = s[2];
    st.mid_lsf_int = s[3];
    st.relax_prev_lsf_interp = s[4];
    st.stab_fac = s[5];
    st.mode_lvq = s[6];
    st.reset_mem_ar = s[7];
    st.mem_ar.copy_from_slice(&case.i16s("mem_ar"));
    st.mem_ma.copy_from_slice(&case.i16s("mem_ma"));
    st.lsf_old.copy_from_slice(&case.i16s("lsf_old"));
    st.lsp_old.copy_from_slice(&case.i16s("lsp_old"));
    st.lsf_adaptive_mean.copy_from_slice(&case.i16s("mean"));
    st
}

fn check_state(case: &Case, st: &DecoderState, suffix: &str) {
    let s = vec![
        st.ber_detect,
        st.next_bit_pos,
        st.safety_net,
        st.mid_lsf_int,
        st.relax_prev_lsf_interp,
        st.stab_fac,
        st.mode_lvq,
        st.reset_mem_ar,
    ];
    check(
        case,
        &format!("st{suffix}"),
        &s,
        &case.out_i16s(&format!("st{suffix}")),
    );
    for (name, rust) in [
        ("mem_ar", &st.mem_ar),
        ("mem_ma", &st.mem_ma),
        ("lsf_old", &st.lsf_old),
        ("lsp_old", &st.lsp_old),
        ("mean", &st.lsf_adaptive_mean),
    ] {
        let name = format!("{name}{suffix}");
        check(case, &name, &rust.to_vec(), &case.out_i16s(&name));
    }
}

#[test]
fn lsf_dec_matches_the_reference() {
    let Some(cases) = corpus("lsf_dec", "lsf_dec") else {
        return;
    };
    for case in &cases {
        let mut st = new_state(case);
        let l_frame = case.i16("l_frame");
        st.l_frame = l_frame;
        st.lsfoldbfi0.copy_from_slice(&case.i16s("lsfoldbfi0"));
        st.lsfoldbfi1.copy_from_slice(&case.i16s("lsfoldbfi1"));
        for f in 0..case.i32("frames") {
            let p = case.i16s(&format!("f{f}"));
            st.core_brate = i32::from(p[1]) * 50;
            st.total_brate = st.core_brate + i32::from(p[2]) * 400;
            st.nelp_mode_dec = p[3];
            st.ppp_mode_dec = p[4];
            st.bwidth = p[5];
            st.prev_bfi = p[8];
            st.rate_switching_reset = p[9];
            st.clas_dec = p[10];
            st.last_core = p[11];
            st.core = 0;
            let mut aq = vec![-5i16; 5 * 17];
            let mut lsf_new = [-3i16; 16];
            let mut lsp_new = [-3i16; 16];
            let mut lsp_mid = [-3i16; 16];
            let mut pred = -7;
            lsf_dec(
                &mut st,
                p[7],
                l_frame,
                p[0],
                p[6],
                &mut aq,
                &mut pred,
                &mut lsf_new,
                &mut lsp_new,
                &mut lsp_mid,
            );
            check(
                case,
                &format!("aq{f}"),
                &aq,
                &case.out_i16s(&format!("aq{f}")),
            );
            check(
                case,
                &format!("lsf{f}"),
                &lsf_new.to_vec(),
                &case.out_i16s(&format!("lsf{f}")),
            );
            check(
                case,
                &format!("lsp{f}"),
                &lsp_new.to_vec(),
                &case.out_i16s(&format!("lsp{f}")),
            );
            check(
                case,
                &format!("mid{f}"),
                &lsp_mid.to_vec(),
                &case.out_i16s(&format!("mid{f}")),
            );
            check(
                case,
                &format!("pred{f}"),
                &pred,
                &case.out_i16(&format!("pred{f}")),
            );
            check_state(case, &st, &f.to_string());
            // The frame-end update the decoder makes (updt_dec_fx).
            st.lsf_old = lsf_new;
            st.lsp_old = lsp_new;
        }
    }
}

#[test]
fn lsf_end_dec_mode2_matches_the_reference() {
    let Some(cases) = corpus("lsf_dec", "lsf_end_dec_mode2") else {
        return;
    };
    for case in &cases {
        let mut st = new_state(case);
        st.core_brate = case.i32("core_brate");
        st.total_brate = st.core_brate;
        let mut lsf = [-3i16; 16];
        let mut pred = -7;
        let mut nb_indices = -9;
        let mut safety_net = st.safety_net;
        lsf_end_dec(
            &mut st,
            1,
            case.i16("coder_type"),
            1 - case.i16("narrow_band"),
            31,
            &mut lsf,
            case.i32("sr_core"),
            case.i32("core_brate"),
            &mut safety_net,
            &case.i16s("param"),
            &mut pred,
            Some(&mut nb_indices),
        );
        st.safety_net = safety_net;
        check(case, "lsf", &lsf.to_vec(), &case.out_i16s("lsf"));
        check(case, "pred", &pred, &case.out_i16("pred"));
        check(case, "nb_indices", &nb_indices, &case.out_i16("nb_indices"));
        check_state(case, &st, "");
    }
}
