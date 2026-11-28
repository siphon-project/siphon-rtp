//! `lib_com/wtda_fx.c` against `fn_wtda`.

use siphon_rtp_codec::evs::com::wtda::{tcx_get_windows_mode1, wtda};

use crate::common::{corpus, mismatch};

#[test]
fn tcx_get_windows_mode1_matches_the_reference() {
    let Some(cases) = corpus("wtda", "windows") else {
        return;
    };
    for case in &cases {
        let (mut lw, mut rw, mut lwi, mut rwi) =
            ([1234; 690], [1234; 420], [1234; 230], [1234; 140]);
        tcx_get_windows_mode1(
            case.i16("left_mode"),
            case.i16("right_mode"),
            &mut lw,
            &mut rw,
            &mut lwi,
            &mut rwi,
            case.i16("L"),
        );
        for (name, rust) in [
            ("left_win", lw.to_vec()),
            ("right_win", rw.to_vec()),
            ("left_win_int", lwi.to_vec()),
            ("right_win_int", rwi.to_vec()),
        ] {
            if let Some(message) = mismatch(case, name, &rust, &case.out_i16s(name)) {
                panic!("{message}");
            }
        }
    }
}

#[test]
fn wtda_matches_the_reference() {
    let Some(cases) = corpus("wtda", "wtda") else {
        return;
    };
    for case in &cases {
        let l = case.i16("L");
        let lu = l as usize;
        let with_old = case.i16("with_old") != 0;
        let mut q = case.i16("Q");
        let mut q_old = case.i16("Qold");
        let mut old = if with_old {
            case.i16s("old")
        } else {
            Vec::new()
        };
        let frames = if with_old { 2 } else { 1 };
        let mut buffer = Vec::new();
        for f in 0..frames {
            buffer = case.i16s(&format!("buffer{f}"));
            let mut out = vec![0i32; lu];
            wtda(
                &mut buffer,
                lu,
                &mut q,
                &mut out,
                if with_old { Some(&mut old[..]) } else { None },
                &mut q_old,
                case.i16("left_mode"),
                case.i16("right_mode"),
                l,
            );
            let name = format!("out{f}");
            if let Some(message) = mismatch(case, &name, &out, &case.out_i32s(&name)) {
                panic!("{message}");
            }
        }
        if let Some(message) = mismatch(case, "Q", &q, &case.out_i16("Q")) {
            panic!("{message}");
        }
        if let Some(message) = mismatch(case, "Qold", &q_old, &case.out_i16("Qold")) {
            panic!("{message}");
        }
        if with_old {
            if let Some(message) = mismatch(case, "old", &old, &case.out_i16s("old")) {
                panic!("{message}");
            }
        }
        if let Some(message) = mismatch(case, "buffer_last", &buffer, &case.out_i16s("buffer_last"))
        {
            panic!("{message}");
        }
    }
}
