//! `lib_com/hvq_pvq_bitalloc_fx.c` against `fn_hvq_pvq_bitalloc`: SWB and FB at 24.4 and 32 kbit/s,
//! budgets from below one band to a whole frame, with and without a dominant high band.

use siphon_rtp_codec::evs::com::hvq_pvq_bitalloc::hvq_pvq_bitalloc;

use crate::common::{corpus, mismatch};

#[test]
fn hvq_pvq_bitalloc_matches_the_reference() {
    let Some(cases) = corpus("hvq_pvq_bitalloc", "hvq_pvq_bitalloc") else {
        return;
    };
    let mut selected = 0;
    let mut empty = 0;
    for case in &cases {
        let mut rk = [-7i16; 8];
        let mut r = case.i16s("r");
        let mut sel_bands = [-7i16; 16];
        let mut n_sel = -7;
        let bands = hvq_pvq_bitalloc(
            case.i16("num_bits"),
            case.i32("brate"),
            case.i16("bwidth"),
            &case.i16s("ynrm"),
            case.i32("man"),
            case.i16("ex"),
            &mut rk,
            &mut r,
            &mut sel_bands,
            &mut n_sel,
        );
        if let Some(message) = [
            mismatch(case, "bands", &bands, &case.out_i16("bands")),
            mismatch(case, "rk", &rk.to_vec(), &case.out_i16s("rk")),
            mismatch(case, "r", &r, &case.out_i16s("r")),
            mismatch(
                case,
                "sel_bands",
                &sel_bands.to_vec(),
                &case.out_i16s("sel_bands"),
            ),
            mismatch(case, "n_sel", &n_sel, &case.out_i16("n_sel")),
        ]
        .into_iter()
        .flatten()
        .next()
        {
            panic!("{message}");
        }
        selected += i32::from(n_sel > 0);
        empty += i32::from(bands == 0);
    }
    assert!(
        selected > 50 && empty > 20,
        "selected {selected}, empty {empty}"
    );
}
