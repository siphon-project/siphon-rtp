//! `lib_com/trans_inv_fx.c` against `fn_trans_inv`: `Inverse_Transform` (long and transient, with
//! the inner frame shorter, equal or longer), and `preecho_sb_fx` over three consecutive frames
//! carrying its state.

use siphon_rtp_codec::evs::com::trans_inv::{inverse_transform, preecho_sb, PreechoState};

use crate::common::{corpus, mismatch, Case};

fn check<T: PartialEq + std::fmt::Debug>(case: &Case, name: &str, rust: &T, reference: &T) {
    if let Some(message) = mismatch(case, name, rust, reference) {
        panic!("{message}");
    }
}

#[test]
fn inverse_transform_matches_the_reference() {
    let Some(cases) = corpus("trans_inv", "inverse_transform") else {
        return;
    };
    for case in &cases {
        let l = case.i16("l");
        let mut out = vec![0x5555_5555; l as usize];
        let mut q = case.i16("q");
        inverse_transform(
            &case.i32s("in"),
            &mut q,
            &mut out,
            case.i16("is_transient"),
            l,
            case.i16("l_inner"),
        );
        check(
            case,
            "out/q",
            &(out, q),
            &(case.out_i32s("out"), case.out_i16("q")),
        );
    }
}

#[test]
fn preecho_sb_matches_the_reference() {
    let Some(cases) = corpus("trans_inv", "preecho_sb") else {
        return;
    };
    for case in &cases {
        let l = case.i16("l");
        let bwidth = case.i16("bwidth");
        let mut memfilt_lb = case.i16("memfilt");
        let mut smoothmem = case.i16("smoothmem");
        let mut wmold_hb = case.i16("wmold_hb");
        let mut prevflag = case.i16("prevflag");
        let mut pastpre = case.i16("pastpre");
        let mut mean_prev_hb = case.i32("mean_prev_hb");
        let mut mean_prev = case.i32("mean_prev");
        let mut mean_prev_nc = case.i32("mean_prev_nc");
        for k in 0..3 {
            let mut rec = case.i16s(&format!("rec{k}"));
            let mut state = PreechoState {
                memfilt_lb: &mut memfilt_lb,
                mean_prev_hb: &mut mean_prev_hb,
                smoothmem: &mut smoothmem,
                mean_prev: &mut mean_prev,
                mean_prev_nc: &mut mean_prev_nc,
                wmold_hb: &mut wmold_hb,
                prevflag: &mut prevflag,
                pastpre: &mut pastpre,
            };
            preecho_sb(
                case.i32(&format!("brate{k}")),
                &case.i32s(&format!("wtda{k}")),
                case.i16(&format!("q32_{k}")),
                &mut rec,
                case.i16(&format!("q16_{k}")),
                l,
                &mut state,
                bwidth,
            );
            check(
                case,
                &format!("rec{k}"),
                &rec,
                &case.out_i16s(&format!("rec{k}")),
            );
            let st = vec![
                i32::from(memfilt_lb),
                mean_prev_hb,
                i32::from(smoothmem),
                mean_prev,
                mean_prev_nc,
                i32::from(wmold_hb),
                i32::from(prevflag),
                i32::from(pastpre),
            ];
            check(
                case,
                &format!("state{k}"),
                &st,
                &case.out_i32s(&format!("state{k}")),
            );
        }
    }
}
